use lettre::{
    message::{header::ContentType, Message, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use rand::Rng;
use serde::Serialize;
use crate::{config::Config, errors::Result};

/// Email service for sending authentication-related emails
#[derive(Clone)]
pub struct EmailService {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from_email: String,
    from_name: String,
    app_name: String,
}

/// Email template data for verification
#[derive(Debug, Clone, Serialize)]
pub struct VerificationEmailData {
    pub user_email: String,
    pub verification_code: String,
    pub app_name: String,
    pub expires_in_minutes: u32,
}

/// Email template data for password reset
#[derive(Debug, Clone, Serialize)]
pub struct ResetEmailData {
    pub user_email: String,
    pub reset_code: String,
    pub app_name: String,
    pub expires_in_minutes: u32,
}

impl EmailService {
    /// Create a new email service
    pub fn new(config: &Config) -> Result<Self> {
        let creds = Credentials::new(
            config.smtp_username.clone(),
            config.smtp_password.clone(),
        );

        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_server)?
            .port(config.smtp_port)
            .credentials(creds)
            .build();

        Ok(Self {
            mailer,
            from_email: config.smtp_from_email.clone(),
            from_name: config.smtp_from_name.clone(),
            app_name: config.app_name.clone(),
        })
    }

    /// Generate a 6-digit verification code
    pub fn generate_verification_code() -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(100000..=999999))
    }

    /// Send email verification code
    pub async fn send_verification_email(
        &self,
        to_email: &str,
        verification_code: &str,
    ) -> Result<()> {
        let data = VerificationEmailData {
            user_email: to_email.to_string(),
            verification_code: verification_code.to_string(),
            app_name: self.app_name.clone(),
            expires_in_minutes: 10,
        };

        let subject = format!("Verify your {} account", self.app_name);
        let html_body = self.render_verification_email_template(&data);
        let text_body = self.render_verification_email_text(&data);

        self.send_email(to_email, &subject, &html_body, &text_body).await
    }

    /// Send password reset code
    pub async fn send_reset_email(
        &self,
        to_email: &str,
        reset_code: &str,
    ) -> Result<()> {
        let data = ResetEmailData {
            user_email: to_email.to_string(),
            reset_code: reset_code.to_string(),
            app_name: self.app_name.clone(),
            expires_in_minutes: 10,
        };

        let subject = format!("Reset your {} password", self.app_name);
        let html_body = self.render_reset_email_template(&data);
        let text_body = self.render_reset_email_text(&data);

        self.send_email(to_email, &subject, &html_body, &text_body).await
    }

    /// Send email with both HTML and text versions
    async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        html_body: &str,
        text_body: &str,
    ) -> Result<()> {
        let message = Message::builder()
            .from(format!("{} <{}>", self.from_name, self.from_email).parse()?)
            .to(to_email.parse()?)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text_body.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body.to_string()),
                    ),
            )?;

        self.mailer.send(message).await?;
        Ok(())
    }

    /// Render HTML template for email verification
    fn render_verification_email_template(&self, data: &VerificationEmailData) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - {app_name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #007bff;
        }}
        .code-box {{
            background-color: #f8f9fa;
            border: 2px dashed #007bff;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 30px 0;
        }}
        .code {{
            font-size: 32px;
            font-weight: bold;
            color: #007bff;
            letter-spacing: 8px;
            font-family: 'Courier New', monospace;
        }}
        .warning {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 14px;
        }}
        .btn {{
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Verification</h1>
            <p>Welcome to {app_name}!</p>
        </div>
        
        <p>Hello,</p>
        <p>Thank you for signing up with {app_name}. To complete your registration, please verify your email address using the code below:</p>
        
        <div class="code-box">
            <div class="code">{verification_code}</div>
            <p style="margin: 10px 0 0 0; color: #6c757d;">Enter this code in the verification form</p>
        </div>
        
        <div class="warning">
            <strong>Important:</strong> This verification code will expire in {expires_in_minutes} minutes for security reasons. If you didn't request this verification, please ignore this email.
        </div>
        
        <p>If you have any questions or need assistance, please contact our support team.</p>
        
        <div class="footer">
            <p>Best regards,<br>The {app_name} Team</p>
            <p style="font-size: 12px; color: #adb5bd;">
                This is an automated message. Please do not reply to this email.
            </p>
        </div>
    </div>
</body>
</html>"#,
            app_name = data.app_name,
            verification_code = data.verification_code,
            expires_in_minutes = data.expires_in_minutes,
        )
    }

    /// Render plain text version for email verification
    fn render_verification_email_text(&self, data: &VerificationEmailData) -> String {
        format!(
            r#"Email Verification - {app_name}

Hello,

Thank you for signing up with {app_name}. To complete your registration, please verify your email address using the code below:

Verification Code: {verification_code}

Enter this code in the verification form.

IMPORTANT: This verification code will expire in {expires_in_minutes} minutes for security reasons. If you didn't request this verification, please ignore this email.

If you have any questions or need assistance, please contact our support team.

Best regards,
The {app_name} Team

This is an automated message. Please do not reply to this email."#,
            app_name = data.app_name,
            verification_code = data.verification_code,
            expires_in_minutes = data.expires_in_minutes,
        )
    }

    /// Render HTML template for password reset
    fn render_reset_email_template(&self, data: &ResetEmailData) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset - {app_name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #dc3545;
        }}
        .code-box {{
            background-color: #f8f9fa;
            border: 2px dashed #dc3545;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 30px 0;
        }}
        .code {{
            font-size: 32px;
            font-weight: bold;
            color: #dc3545;
            letter-spacing: 8px;
            font-family: 'Courier New', monospace;
        }}
        .warning {{
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 20px 0;
        }}
        .security-notice {{
            background-color: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 15px;
            margin: 20px 0;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset</h1>
            <p>{app_name} Security</p>
        </div>
        
        <p>Hello,</p>
        <p>We received a request to reset the password for your {app_name} account. Use the code below to reset your password:</p>
        
        <div class="code-box">
            <div class="code">{reset_code}</div>
            <p style="margin: 10px 0 0 0; color: #6c757d;">Enter this code to reset your password</p>
        </div>
        
        <div class="warning">
            <strong>Security Notice:</strong> This reset code will expire in {expires_in_minutes} minutes. If you didn't request this password reset, please ignore this email and consider changing your password as a precaution.
        </div>
        
        <div class="security-notice">
            <strong>Security Tips:</strong>
            <ul style="margin: 10px 0;">
                <li>Never share your reset code with anyone</li>
                <li>Create a strong, unique password</li>
                <li>Enable two-factor authentication if available</li>
            </ul>
        </div>
        
        <p>If you continue to have issues or didn't request this reset, please contact our support team immediately.</p>
        
        <div class="footer">
            <p>Best regards,<br>The {app_name} Security Team</p>
            <p style="font-size: 12px; color: #adb5bd;">
                This is an automated security message. Please do not reply to this email.
            </p>
        </div>
    </div>
</body>
</html>"#,
            app_name = data.app_name,
            reset_code = data.reset_code,
            expires_in_minutes = data.expires_in_minutes,
        )
    }

    /// Render plain text version for password reset
    fn render_reset_email_text(&self, data: &ResetEmailData) -> String {
        format!(
            r#"Password Reset - {app_name}

Hello,

We received a request to reset the password for your {app_name} account. Use the code below to reset your password:

Reset Code: {reset_code}

Enter this code to reset your password.

SECURITY NOTICE: This reset code will expire in {expires_in_minutes} minutes. If you didn't request this password reset, please ignore this email and consider changing your password as a precaution.

Security Tips:
- Never share your reset code with anyone
- Create a strong, unique password  
- Enable two-factor authentication if available

If you continue to have issues or didn't request this reset, please contact our support team immediately.

Best regards,
The {app_name} Security Team

This is an automated security message. Please do not reply to this email."#,
            app_name = data.app_name,
            reset_code = data.reset_code,
            expires_in_minutes = data.expires_in_minutes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> Config {
        Config {
            database_url: "sqlite::memory:".to_string(),
            redis_url: "redis://127.0.0.1:6379".to_string(),
            jwt_secret: "test-secret-at-least-32-chars-long".to_string(),
            jwt_access_token_expires_in: 900,
            jwt_refresh_token_expires_in: 604800,
            smtp_server: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "test@example.com".to_string(),
            smtp_password: "test-password".to_string(),
            smtp_from_email: "noreply@example.com".to_string(),
            smtp_from_name: "Test App".to_string(),
            server_host: "127.0.0.1".to_string(),
            server_port: 3001,
            cors_origins: vec!["http://localhost:3000".to_string()],
            app_name: "Test App".to_string(),
            app_env: "test".to_string(),
            log_level: "debug".to_string(),
            rate_limit_enabled: true,
        }
    }

    #[test]
    fn test_generate_verification_code() {
        let code = EmailService::generate_verification_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        
        // Generate multiple codes to ensure randomness
        let codes: Vec<_> = (0..10).map(|_| EmailService::generate_verification_code()).collect();
        assert!(codes.iter().any(|c| c != &codes[0]), "Codes should be random");
    }

    #[tokio::test]
    async fn test_email_template_rendering() {
        let config = create_test_config();
        let service = EmailService::new(&config).unwrap();

        let verification_data = VerificationEmailData {
            user_email: "test@example.com".to_string(),
            verification_code: "123456".to_string(),
            app_name: "Test App".to_string(),
            expires_in_minutes: 10,
        };

        let html = service.render_verification_email_template(&verification_data);
        let text = service.render_verification_email_text(&verification_data);

        assert!(html.contains("123456"));
        assert!(html.contains("Test App"));
        assert!(html.contains("10 minutes"));
        
        assert!(text.contains("123456"));
        assert!(text.contains("Test App"));
        assert!(text.contains("10 minutes"));
    }

    #[tokio::test]
    async fn test_reset_email_template_rendering() {
        let config = create_test_config();
        let service = EmailService::new(&config).unwrap();

        let reset_data = ResetEmailData {
            user_email: "test@example.com".to_string(),
            reset_code: "789012".to_string(),
            app_name: "Test App".to_string(),
            expires_in_minutes: 10,
        };

        let html = service.render_reset_email_template(&reset_data);
        let text = service.render_reset_email_text(&reset_data);

        assert!(html.contains("789012"));
        assert!(html.contains("Test App"));
        assert!(html.contains("10 minutes"));
        assert!(html.contains("Security"));
        
        assert!(text.contains("789012"));
        assert!(text.contains("Test App"));
        assert!(text.contains("10 minutes"));
        assert!(text.contains("Security"));
    }

    #[tokio::test]
    async fn test_email_service_creation() {
        let config = create_test_config();
        let result = EmailService::new(&config);
        
        // Note: This will fail in test environment without real SMTP server
        // but we're testing the structure and configuration parsing
        assert!(result.is_ok());
        
        let service = result.unwrap();
        assert_eq!(service.from_email, "noreply@example.com");
        assert_eq!(service.from_name, "Test App");
        assert_eq!(service.app_name, "Test App");
    }
}