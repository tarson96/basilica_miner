#!/bin/bash
set -e

# Basilica Telemetry Deployment Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/ansible"

# Default values
INVENTORY="inventory"
TAGS=""
CHECK_MODE=""
VAULT_PASSWORD=""
FORCE_RECREATE=""
VERBOSE=""

# Function to print output
print_status() {
    echo "[INFO] $1"
}

print_success() {
    echo "[SUCCESS] $1"
}

print_warning() {
    echo "[WARNING] $1"
}

print_error() {
    echo "[ERROR] $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy Basilica telemetry stack using Ansible

OPTIONS:
    -i, --inventory FILE     Inventory file (default: inventory)
    -t, --tags TAGS         Run only tasks tagged with these tags
    -c, --check             Run in check mode (dry run)
    -v, --verbose           Verbose output (-vvv)
    -f, --force             Force recreation of all services
    --vault-password FILE   Vault password file
    --vault-prompt          Prompt for vault password
    -h, --help              Show this help message

TAGS:
    docker                  Install and configure Docker
    telemetry              Deploy telemetry services
    nginx                  Configure NGINX reverse proxy

EXAMPLES:
    $0                      # Standard deployment
    $0 -c                   # Dry run
    $0 -t docker            # Install Docker only
    $0 -t telemetry         # Deploy services only
    $0 -f                   # Force recreation
    $0 --vault-prompt       # Prompt for vault password

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--inventory)
            INVENTORY="$2"
            shift 2
            ;;
        -t|--tags)
            TAGS="--tags $2"
            shift 2
            ;;
        -c|--check)
            CHECK_MODE="--check"
            shift
            ;;
        -v|--verbose)
            VERBOSE="-vvv"
            shift
            ;;
        -f|--force)
            FORCE_RECREATE="-e basilica_force_recreate=true"
            shift
            ;;
        --vault-password)
            VAULT_PASSWORD="--vault-password-file $2"
            shift 2
            ;;
        --vault-prompt)
            VAULT_PASSWORD="--ask-vault-pass"
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option $1"
            show_usage
            exit 1
            ;;
    esac
done

# Pre-flight checks
print_status "Running pre-flight checks..."

# Check if ansible is installed
if ! command -v ansible-playbook &> /dev/null; then
    print_error "ansible-playbook is not installed or not in PATH"
    exit 1
fi

# Check if inventory file exists
if [[ ! -f "$INVENTORY" ]]; then
    print_error "Inventory file '$INVENTORY' not found"
    print_warning "Copy inventory.example to inventory and configure your hosts"
    exit 1
fi

# Check if required configuration files exist
if [[ ! -f "group_vars/all.yml" ]]; then
    print_error "Configuration file 'group_vars/all.yml' not found"
    print_warning "Copy group_vars/all.yml.example to group_vars/all.yml and configure your settings"
    exit 1
fi

# Check if playbook exists
if [[ ! -f "playbook.yml" ]]; then
    print_error "Playbook file 'playbook.yml' not found"
    exit 1
fi

print_success "Pre-flight checks passed"

# Build ansible command
ANSIBLE_CMD="ansible-playbook -i $INVENTORY playbook.yml"

if [[ -n "$TAGS" ]]; then
    ANSIBLE_CMD="$ANSIBLE_CMD $TAGS"
fi

if [[ -n "$CHECK_MODE" ]]; then
    ANSIBLE_CMD="$ANSIBLE_CMD $CHECK_MODE"
    print_status "Running in check mode (dry run)"
fi

if [[ -n "$VERBOSE" ]]; then
    ANSIBLE_CMD="$ANSIBLE_CMD $VERBOSE"
fi

if [[ -n "$VAULT_PASSWORD" ]]; then
    ANSIBLE_CMD="$ANSIBLE_CMD $VAULT_PASSWORD"
fi

if [[ -n "$FORCE_RECREATE" ]]; then
    ANSIBLE_CMD="$ANSIBLE_CMD $FORCE_RECREATE"
    print_warning "Force recreation enabled - all services will be recreated"
fi

# Show deployment information
print_status "Deployment Configuration:"
echo "  Inventory: $INVENTORY"
echo "  Playbook: playbook.yml"
if [[ -n "$TAGS" ]]; then
    echo "  Tags: ${TAGS#--tags }"
fi
if [[ -n "$CHECK_MODE" ]]; then
    echo "  Mode: Check (dry run)"
else
    echo "  Mode: Deploy"
fi

# Confirm deployment
if [[ -z "$CHECK_MODE" ]]; then
    echo
    read -p "Proceed with deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Deployment cancelled"
        exit 0
    fi
fi

# Run ansible playbook
print_status "Starting deployment..."
print_status "Command: $ANSIBLE_CMD"
echo

# Execute the command
if eval $ANSIBLE_CMD; then
    echo
    print_success "Deployment completed successfully!"

    if [[ -z "$CHECK_MODE" ]]; then
        echo
        print_status "Access your telemetry stack:"
        echo "  Prometheus: https://basilica-telemetry.tplr.ai"
        echo "  Loki:       https://basilica-logs.tplr.ai"
        echo "  Grafana:    https://basilica-grafana.tplr.ai"
        echo
        print_status "Grafana has anonymous access enabled - no login required!"
        print_warning "Admin credentials: admin / basilica_admin"
    fi
else
    echo
    print_error "Deployment failed!"
    exit 1
fi
