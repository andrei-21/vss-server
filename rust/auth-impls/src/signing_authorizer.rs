//! [`Authorizer`] implementation using `vss-signing-auth`.

use api::auth::{AuthResponse, Authorizer};
use api::error::VssError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;
use vss_signing_auth::authenticate;

/// An [`Authorizer`] that validates `vss-signing-auth` request headers and uses the request's
/// signing public key as the `user_token`.
pub struct SigningAuthorizer {
	max_skew: Duration,
	expected_api_key: Option<String>,
}

impl SigningAuthorizer {
	/// Creates a new [`SigningAuthorizer`].
	pub fn new(max_skew: Duration, expected_api_key: Option<String>) -> Self {
		Self { max_skew, expected_api_key }
	}
}

#[async_trait]
impl Authorizer for SigningAuthorizer {
	async fn verify(
		&self, headers_map: &HashMap<String, String>,
	) -> Result<AuthResponse, VssError> {
		let pubkey_hex = authenticate(headers_map, self.max_skew, self.expected_api_key.as_deref())
			.map_err(|e| VssError::AuthError(e.to_string()))?;

		Ok(AuthResponse { user_token: pubkey_hex })
	}
}
