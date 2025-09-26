use authentification::services::email::EmailService;
use authentification::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Test d'envoi d'email...");

    // Charger la configuration
    let config = Config::from_env()?;
    
    // Créer le service email
    let email_service = EmailService::new(
        &config.smtp_server,
        config.smtp_port,
        &config.smtp_username,
        &config.smtp_password,
        &config.smtp_from_email,
        &config.smtp_from_name,
    ).await?;

    // Générer un code de test
    let verification_code = "123456";
    let test_email = "bianca.rossi356@gmail.com"; // L'email de test

    println!("📧 Envoi d'un email de test à: {}", test_email);
    
    // Envoyer l'email de vérification
    match email_service.send_verification_email(test_email, verification_code).await {
        Ok(_) => {
            println!("✅ Email envoyé avec succès !");
            println!("📬 Vérifiez votre boîte mail pour le code: {}", verification_code);
        },
        Err(e) => {
            println!("❌ Erreur lors de l'envoi: {}", e);
            return Err(e.into());
        }
    }

    println!("🧪 Test terminé.");
    Ok(())
}