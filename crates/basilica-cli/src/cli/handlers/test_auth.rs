//! Test authentication token functionality

use crate::client::create_authenticated_client;
use crate::config::CliConfig;
use crate::error::{CliError, Result};
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use tracing::{debug, info};

/// Auth0 userinfo response
#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    sub: String, // Subject - unique identifier
    name: Option<String>,
    nickname: Option<String>,
    picture: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    updated_at: Option<String>,
}

/// Mask sensitive information in user ID (OAuth sub field)
fn mask_user_id(id: &str) -> String {
    // For OAuth providers like google-oauth2|123456789, mask the numeric ID
    if let Some(pipe_idx) = id.find('|') {
        let provider = &id[..=pipe_idx];
        let user_id = &id[pipe_idx + 1..];

        // Mask the user ID part, showing only first and last 2 chars if long enough
        let masked_id = if user_id.len() > 6 {
            format!("{}...{}", &user_id[..2], &user_id[user_id.len() - 2..])
        } else if user_id.len() > 2 {
            format!("{}...", &user_id[..1])
        } else {
            "***".to_string()
        };

        format!("{}{}", provider, masked_id)
    } else {
        // For other ID formats, mask middle portion
        if id.len() > 8 {
            format!("{}...{}", &id[..3], &id[id.len() - 3..])
        } else if id.len() > 4 {
            format!("{}...", &id[..2])
        } else {
            "***".to_string()
        }
    }
}

/// Mask email address to show only domain
fn mask_email(email: &str) -> String {
    if let Some(at_idx) = email.find('@') {
        let domain = &email[at_idx + 1..];
        format!("***@{}", domain)
    } else {
        // If it's not a valid email format, mask it entirely
        "***".to_string()
    }
}

/// Decode JWT payload to extract scopes
fn decode_jwt_scopes(token: &str) -> Option<Vec<String>> {
    // JWT has three parts separated by dots: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        debug!("Invalid JWT format - expected 3 parts, got {}", parts.len());
        return None;
    }

    // Decode the payload (second part)
    let payload_str = parts[1];

    // Add padding if necessary for base64 decoding
    let padded = match payload_str.len() % 4 {
        2 => format!("{}==", payload_str),
        3 => format!("{}=", payload_str),
        _ => payload_str.to_string(),
    };

    // Decode base64 (use URL_SAFE since we added padding)
    match URL_SAFE.decode(padded.as_bytes()) {
        Ok(decoded_bytes) => {
            // Parse JSON
            match serde_json::from_slice::<Value>(&decoded_bytes) {
                Ok(json) => {
                    debug!(
                        "JWT payload fields: {:?}",
                        json.as_object().map(|o| o.keys().collect::<Vec<_>>())
                    );

                    // Extract scope field (try both 'scope' and 'permissions')
                    if let Some(scope_value) = json.get("scope") {
                        if let Some(scope_str) = scope_value.as_str() {
                            // Split scopes by space (OAuth2 standard)
                            let scopes: Vec<String> = scope_str
                                .split_whitespace()
                                .map(|s| s.to_string())
                                .collect();
                            debug!("Decoded scopes from JWT 'scope' field: {:?}", scopes);
                            return Some(scopes);
                        }
                    }

                    // Also check 'permissions' field (Auth0 sometimes uses this)
                    if let Some(permissions) = json.get("permissions") {
                        if let Some(perms_array) = permissions.as_array() {
                            let scopes: Vec<String> = perms_array
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            if !scopes.is_empty() {
                                debug!("Decoded scopes from JWT 'permissions' field: {:?}", scopes);
                                return Some(scopes);
                            }
                        }
                    }

                    debug!("No 'scope' or 'permissions' field found in JWT");
                    None
                }
                Err(e) => {
                    debug!("Failed to parse JWT payload as JSON: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            debug!("Failed to decode JWT payload from base64: {}", e);
            debug!("Attempting fallback decoding without padding...");

            // Fallback: try without padding using URL_SAFE_NO_PAD
            match URL_SAFE_NO_PAD.decode(payload_str.as_bytes()) {
                Ok(decoded_bytes) => match serde_json::from_slice::<Value>(&decoded_bytes) {
                    Ok(json) => {
                        // Check 'scope' field
                        if let Some(scope_value) = json.get("scope") {
                            if let Some(scope_str) = scope_value.as_str() {
                                let scopes: Vec<String> = scope_str
                                    .split_whitespace()
                                    .map(|s| s.to_string())
                                    .collect();
                                debug!(
                                    "Decoded scopes from JWT 'scope' field (fallback): {:?}",
                                    scopes
                                );
                                return Some(scopes);
                            }
                        }

                        // Also check 'permissions' field
                        if let Some(permissions) = json.get("permissions") {
                            if let Some(perms_array) = permissions.as_array() {
                                let scopes: Vec<String> = perms_array
                                    .iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect();
                                if !scopes.is_empty() {
                                    debug!("Decoded scopes from JWT 'permissions' field (fallback): {:?}", scopes);
                                    return Some(scopes);
                                }
                            }
                        }

                        debug!("No 'scope' or 'permissions' field found in JWT (fallback)");
                        None
                    }
                    Err(_) => None,
                },
                Err(e2) => {
                    debug!("Fallback decoding also failed: {}", e2);
                    None
                }
            }
        }
    }
}

/// Test the authentication token by calling Auth0's /userinfo endpoint
pub async fn handle_test_auth(
    config: &CliConfig,
    _config_path: impl AsRef<Path>,
    no_auth: bool,
) -> Result<()> {
    println!("Testing authentication token...\n");

    // Get the authenticated client
    let client = create_authenticated_client(config, no_auth).await?;

    // Use Auth0 domain from constants
    let userinfo_url = format!("https://{}/userinfo", basilica_common::auth0_domain());

    debug!("Calling Auth0 userinfo endpoint: {}", userinfo_url);

    // Make a direct HTTP request to the userinfo endpoint
    let http_client = reqwest::Client::new();

    // Get the bearer token from our client
    let token = client.get_bearer_token().await.ok_or_else(|| {
        CliError::internal("No authentication token found. Please run 'basilica login' first")
    })?;

    let response = http_client
        .get(&userinfo_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| CliError::internal(format!("Failed to call userinfo endpoint: {}", e)))?;

    let status = response.status();

    if status.is_success() {
        let user_info: UserInfo = response
            .json()
            .await
            .map_err(|e| CliError::internal(format!("Failed to parse userinfo response: {}", e)))?;

        println!("Token is valid!\n");
        println!("User Information:");
        println!("─────────────────");

        // Mask the user ID (OAuth subject)
        println!("  ID: {}", mask_user_id(&user_info.sub));

        // Display masked email if present
        if let Some(email) = &user_info.email {
            println!("  Email: {}", mask_email(email));
            if let Some(verified) = user_info.email_verified {
                println!("  Email Verified: {}", verified);
            }
        }

        if let Some(updated) = &user_info.updated_at {
            println!("  Last Updated: {}", updated);
        }

        // Display OAuth scopes from the JWT token
        println!("\nToken Scopes:");
        println!("─────────────");
        match decode_jwt_scopes(&token) {
            Some(scopes) => {
                if scopes.is_empty() {
                    println!("  No scopes found in token");
                } else {
                    for scope in &scopes {
                        println!("  • {}", scope);
                    }
                }
            }
            None => {
                println!("  Unable to decode scopes from token");
                println!("  (This may indicate an issue with the token format)");
            }
        }

        println!("\nAuthentication is working correctly!");
        info!("Auth0 token validation successful");
    } else if status.as_u16() == 401 {
        println!("Token is invalid or expired");
        println!("\nPlease run 'basilica login' to get a new token");
        return Err(CliError::internal("Invalid or expired token"));
    } else if status.as_u16() == 429 {
        println!("Rate limited (max 5 requests per minute)");
        println!("Please wait a moment and try again");
        return Err(CliError::internal("Rate limited by Auth0"));
    } else {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        println!("Unexpected error: {}", status);
        println!("Response: {}", error_text);
        return Err(CliError::internal(format!("Unexpected error: {}", status)));
    }

    Ok(())
}

/// Test API authentication by making a request to your Basilica API
pub async fn handle_test_api_auth(
    config: &CliConfig,
    _config_path: impl AsRef<Path>,
    no_auth: bool,
) -> Result<()> {
    println!("Testing Basilica API authentication...\n");

    // Create authenticated client
    let client = create_authenticated_client(config, no_auth).await?;

    // Try to call the health endpoint
    match client.health_check().await {
        Ok(health) => {
            println!("Successfully connected to Basilica API");
            println!("  Status: {}", health.status);
            println!("  Version: {}", health.version);
            println!("  Timestamp: {}", health.timestamp);
        }
        Err(e) => {
            println!("Failed to connect to Basilica API");
            println!("  Error: {}", e);
            println!("  Note: Health endpoint requires full authentication");
            println!("  Run 'basilica login' to authenticate if you haven't already");
            return Err(CliError::internal(format!("API connection failed: {}", e)));
        }
    }

    Ok(())
}
