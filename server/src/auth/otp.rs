//! Email OTP authentication using Resend API.

use rand::Rng;
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::Resend;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// OTP TTL in milliseconds (5 minutes).
pub const OTP_TTL_MS: i64 = 5 * 60 * 1000;

/// Email OTP manager using Resend API.
#[derive(Clone)]
pub struct OtpManager {
    client: Resend,
    from: String,
}

impl OtpManager {
    /// Create a new OTP manager from config.
    pub fn new(config: &Config) -> AppResult<Self> {
        let client = Resend::new(&config.resend_api_key);

        Ok(Self {
            client,
            from: config.resend_from.clone(),
        })
    }

    /// Generate a 6-digit OTP code.
    pub fn generate_code() -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(0..1_000_000))
    }

    /// Send an OTP email.
    pub async fn send_otp_email(&self, to_email: &str, code: &str) -> AppResult<()> {
        let subject = "Your Handrive verification code";
        let body = format!(
            r#"Your verification code is: {}

This code will expire in 5 minutes.

If you didn't request this code, you can safely ignore this email.

- The Handrive Team"#,
            code
        );

        let email = CreateEmailBaseOptions::new(&self.from, [to_email], subject)
            .with_text(&body);

        self.client.emails.send(email).await.map_err(|e| {
            tracing::error!(
                email = %to_email,
                error = %e,
                error_debug = ?e,
                "Failed to send OTP email"
            );
            AppError::Internal(anyhow::anyhow!("Failed to send email: {}", e))
        })?;

        tracing::info!(email = %to_email, "OTP email sent");
        Ok(())
    }

    /// Send an invitation email.
    pub async fn send_invite_email(
        &self,
        to_email: &str,
        inviter_name: &str,
        inviter_email: &str,
        message: Option<&str>,
    ) -> AppResult<()> {
        let subject = format!("{} invited you to Handrive", inviter_name);
        let custom_message = message
            .map(|m| format!("\n\nMessage from {}:\n\"{}\"\n", inviter_name, m))
            .unwrap_or_default();

        let body = format!(
            r#"Hi!

{} ({}) has invited you to join Handrive, a privacy-first peer-to-peer file sharing app.
{}
Get started by installing Handrive app at: https://handrive.ai

- The Handrive Team"#,
            inviter_name, inviter_email, custom_message
        );

        let email = CreateEmailBaseOptions::new(&self.from, [to_email], &subject)
            .with_text(&body);

        self.client.emails.send(email).await.map_err(|e| {
            tracing::error!(
                email = %to_email,
                inviter = %inviter_email,
                error = %e,
                "Failed to send invite email"
            );
            AppError::Internal(anyhow::anyhow!("Failed to send email: {}", e))
        })?;

        tracing::info!(email = %to_email, inviter = %inviter_email, "Invite email sent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_length() {
        let code = OtpManager::generate_code();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_generate_code_all_numeric() {
        let code = OtpManager::generate_code();
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_code_zero_padding() {
        // Run many times to increase chance of hitting a code < 100000
        let mut saw_leading_zero = false;
        for _ in 0..10_000 {
            let code = OtpManager::generate_code();
            assert_eq!(code.len(), 6, "Code must always be 6 chars: {}", code);
            if code.starts_with('0') {
                saw_leading_zero = true;
                break;
            }
        }
        // Probability of never seeing a leading zero in 10k runs is ~(0.9)^10000 ≈ 0
        assert!(saw_leading_zero, "Expected at least one code with leading zero in 10k runs");
    }

    #[test]
    fn test_generate_code_range() {
        for _ in 0..1000 {
            let code = OtpManager::generate_code();
            let num: u32 = code.parse().unwrap();
            assert!(num < 1_000_000);
        }
    }

    #[test]
    fn test_generate_code_not_all_identical() {
        let codes: std::collections::HashSet<String> =
            (0..100).map(|_| OtpManager::generate_code()).collect();
        // 100 random codes should not all be identical
        assert!(codes.len() > 1, "All 100 generated codes were identical");
    }
}
