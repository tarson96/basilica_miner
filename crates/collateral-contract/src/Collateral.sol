// SPDX-License-Identifier: UNLICENSED
// the source code is from  https://github.com/Datura-ai/celium-collateral-contracts/src/Collateral.sol
// with commit hash ed1ddd2578942af7050995b9c9db81d2b7ba2e42

pragma solidity ^0.8.28;

contract Collateral {
    uint16 public NETUID;
    address public TRUSTEE;
    uint64 public DECISION_TIMEOUT;
    uint256 public MIN_COLLATERAL_INCREASE;

    mapping(bytes32 => mapping(bytes16 => address)) public executorToMiner;
    mapping(bytes32 => mapping(bytes16 => uint256)) public collaterals;
    mapping(uint256 => Reclaim) public reclaims;

    mapping(bytes32 => mapping(bytes16 => uint256))
        private collateralUnderPendingReclaims;
    uint256 private nextReclaimId;

    struct Reclaim {
        bytes32 hotkey;
        bytes16 executorId;
        address miner;
        uint256 amount;
        uint64 denyTimeout;
    }

    event Deposit(
        bytes32 indexed hotkey,
        bytes16 indexed executorId,
        address indexed miner,
        uint256 amount
    );
    event ReclaimProcessStarted(
        uint256 indexed reclaimRequestId,
        bytes32 indexed hotkey,
        bytes16 indexed executorId,
        address miner,
        uint256 amount,
        uint64 expirationTime,
        string url,
        bytes16 urlContentMd5Checksum
    );
    event Reclaimed(
        uint256 indexed reclaimRequestId,
        bytes32 indexed hotkey,
        bytes16 indexed executorId,
        address miner,
        uint256 amount
    );
    event Denied(
        uint256 indexed reclaimRequestId,
        string url,
        bytes16 urlContentMd5Checksum
    );
    event Slashed(
        bytes32 indexed hotkey,
        bytes16 indexed executorId,
        address indexed miner,
        uint256 amount,
        string url,
        bytes16 urlContentMd5Checksum
    );

    error AmountZero();
    error BeforeDenyTimeout();
    error ExecutorNotOwned();
    error InsufficientAmount();
    error InvalidDepositMethod();
    error NotTrustee();
    error PastDenyTimeout();
    error ReclaimNotFound();
    error TransferFailed();
    error InsufficientCollateralForReclaim();

    /// @notice Initializes a new Collateral contract with specified parameters
    /// @param netuid The netuid of the subnet
    /// @param trustee H160 address of the trustee who has permissions to slash collateral or deny reclaim requests
    /// @param minCollateralIncrease The minimum amount that can be deposited or reclaimed
    /// @param decisionTimeout The time window (in seconds) for the trustee to deny a reclaim request
    /// @dev Reverts if any of the arguments is zero
    constructor(
        uint16 netuid,
        address trustee,
        uint256 minCollateralIncrease,
        uint64 decisionTimeout
    ) {
        // custom errors are not used here because it's a 1-time setup
        require(trustee != address(0), "Trustee address must be non-zero");
        require(
            minCollateralIncrease > 0,
            "Min collateral increase must be greater than 0"
        );
        require(decisionTimeout > 0, "Decision timeout must be greater than 0");

        NETUID = netuid;
        TRUSTEE = trustee;
        MIN_COLLATERAL_INCREASE = minCollateralIncrease;
        DECISION_TIMEOUT = decisionTimeout;
    }

    modifier onlyTrustee() {
        if (msg.sender != TRUSTEE) {
            revert NotTrustee();
        }
        _;
    }

    // Allow deposits only via deposit() function
    receive() external payable {
        revert InvalidDepositMethod();
    }

    // Allow deposits only via deposit() function
    fallback() external payable {
        revert InvalidDepositMethod();
    }

    /// @notice Allows users to deposit collateral into the contract for a specific executor
    /// @param hotkey The netuid key for the subnet
    /// @param executorId The ID of the executor to deposit collateral for
    /// @dev The first deposit for an executorId sets the owner. Subsequent deposits must be from the owner.
    /// @dev The deposited amount must be greater than or equal to MIN_COLLATERAL_INCREASE
    /// @dev If it's not revert with InsufficientAmount error
    /// @dev Emits a Deposit event with the hotkey, executorId, sender's address and deposited amount
    function deposit(bytes32 hotkey, bytes16 executorId) external payable {
        if (msg.value < MIN_COLLATERAL_INCREASE) {
            revert InsufficientAmount();
        }

        address owner = executorToMiner[hotkey][executorId];
        if (owner == address(0)) {
            executorToMiner[hotkey][executorId] = msg.sender;
        } else if (owner != msg.sender) {
            revert ExecutorNotOwned();
        }

        collaterals[hotkey][executorId] += msg.value;
        emit Deposit(hotkey, executorId, msg.sender, msg.value);
    }

    /// @notice Initiates a process to reclaim all available collateral from a specific executor
    /// @dev If it's not denied by the trustee, the collateral will be available for withdrawal after DECISION_TIMEOUT
    /// @param hotkey The netuid key for the subnet
    /// @param executorId The ID of the executor to reclaim collateral from
    /// @param url URL containing information about the reclaim request
    /// @param urlContentMd5Checksum MD5 checksum of the content at the provided URL
    /// @dev Emits ReclaimProcessStarted event with reclaim details and timeout
    /// @dev Reverts with ExecutorNotOwned if caller is not the owner of the executor
    /// @dev Reverts with AmountZero if there is no available collateral to reclaim
    function reclaimCollateral(
        bytes32 hotkey,
        bytes16 executorId,
        string calldata url,
        bytes16 urlContentMd5Checksum
    ) external {
        if (executorToMiner[hotkey][executorId] != msg.sender) {
            revert ExecutorNotOwned();
        }

        uint256 collateral = collaterals[hotkey][executorId];
        uint256 pendingCollateral = collateralUnderPendingReclaims[hotkey][
            executorId
        ];
        uint256 amount = collateral - pendingCollateral;

        if (amount == 0) {
            revert AmountZero();
        }

        uint64 expirationTime = uint64(block.timestamp) + DECISION_TIMEOUT;
        reclaims[++nextReclaimId] = Reclaim(
            hotkey,
            executorId,
            msg.sender,
            amount,
            expirationTime
        );
        collateralUnderPendingReclaims[hotkey][executorId] += amount;

        emit ReclaimProcessStarted(
            nextReclaimId,
            hotkey,
            executorId,
            msg.sender,
            amount,
            expirationTime,
            url,
            urlContentMd5Checksum
        );
    }

    /// @notice Finalizes a reclaim request and transfers the collateral to the depositor if conditions are met
    /// @dev Can be called by anyone
    /// @dev Requires that deny timeout has expired
    /// @dev If the miner has been slashed and their collateral is insufficient for a reclaim, the reclaim is canceled but transactions completes successfully allowing to request another reclaim
    /// @param reclaimRequestId The ID of the reclaim request to finalize
    /// @dev Emits Reclaimed event with reclaim details if successful
    /// @dev Reverts with ReclaimNotFound if the reclaim request doesn't exist or was denied
    /// @dev Reverts with BeforeDenyTimeout if the deny timeout hasn't expired
    /// @dev Reverts with TransferFailed if the TAO transfer fails
    function finalizeReclaim(uint256 reclaimRequestId) external {
        Reclaim storage reclaim = reclaims[reclaimRequestId];
        if (reclaim.amount == 0) {
            revert ReclaimNotFound();
        }
        if (reclaim.denyTimeout >= block.timestamp) {
            revert BeforeDenyTimeout();
        }

        bytes32 hotkey = reclaim.hotkey;
        bytes16 executorId = reclaim.executorId;
        address miner = reclaim.miner;
        uint256 amount = reclaim.amount;

        delete reclaims[reclaimRequestId];
        collateralUnderPendingReclaims[hotkey][executorId] -= amount;

        if (collaterals[hotkey][executorId] < amount) {
            // miner got slashed and can't withdraw
            revert InsufficientCollateralForReclaim();
        }

        collaterals[hotkey][executorId] -= amount;

        emit Reclaimed(reclaimRequestId, hotkey, executorId, miner, amount);

        // check-effect-interact pattern used to prevent reentrancy attacks
        (bool success, ) = payable(miner).call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }
        executorToMiner[hotkey][executorId] = address(0);
    }

    /// @notice Allows the trustee to deny a pending reclaim request before the timeout expires
    /// @dev Can only be called by the trustee (address set in constructor)
    /// @dev Must be called before the deny timeout expires
    /// @dev Removes the reclaim request and frees up the collateral for other reclaims
    /// @param reclaimRequestId The ID of the reclaim request to deny
    /// @param url URL containing the reason of denial
    /// @param urlContentMd5Checksum MD5 checksum of the content at the provided URL
    /// @dev Emits Denied event with the reclaim request ID
    /// @dev Reverts with NotTrustee if called by non-trustee address
    /// @dev Reverts with ReclaimNotFound if the reclaim request doesn't exist
    /// @dev Reverts with PastDenyTimeout if the timeout has already expired
    function denyReclaimRequest(
        uint256 reclaimRequestId,
        string calldata url,
        bytes16 urlContentMd5Checksum
    ) external onlyTrustee {
        Reclaim storage reclaim = reclaims[reclaimRequestId];
        if (reclaim.amount == 0) {
            revert ReclaimNotFound();
        }
        if (reclaim.denyTimeout < block.timestamp) {
            revert PastDenyTimeout();
        }

        collateralUnderPendingReclaims[reclaim.hotkey][
            reclaim.executorId
        ] -= reclaim.amount;
        emit Denied(reclaimRequestId, url, urlContentMd5Checksum);

        delete reclaims[reclaimRequestId];
    }

    /// @notice Allows the trustee to slash a miner's collateral for a specific executor
    /// @dev Can only be called by the trustee (address set in constructor)
    /// @dev Removes the collateral from the executor and burns it
    /// @param hotkey The netuid key for the subnet
    /// @param executorId The ID of the executor to slash
    /// @param url URL containing the reason for slashing
    /// @param urlContentMd5Checksum MD5 checksum of the content at the provided URL
    /// @dev Emits Slashed event with the executor's ID, miner's address and the amount slashed
    /// @dev Reverts with AmountZero if there is no collateral to slash
    /// @dev Reverts with TransferFailed if the TAO transfer fails
    function slashCollateral(
        bytes32 hotkey,
        bytes16 executorId,
        string calldata url,
        bytes16 urlContentMd5Checksum
    ) external onlyTrustee {
        uint256 amount = collaterals[hotkey][executorId];

        if (amount == 0) {
            revert AmountZero();
        }

        collaterals[hotkey][executorId] = 0;
        address miner = executorToMiner[hotkey][executorId];

        // burn the collateral
        (bool success, ) = payable(address(0)).call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }
        executorToMiner[hotkey][executorId] = address(0);
        emit Slashed(
            hotkey,
            executorId,
            miner,
            amount,
            url,
            urlContentMd5Checksum
        );
    }
}
