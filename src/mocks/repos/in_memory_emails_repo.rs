use crate::repos::emails_repo::EmailsRepo;
use async_trait::async_trait;
use reqwest::Error;

/// In-memory mock for EmailsRepo.
/// IMPORTANT: Emails are logged but not actually sent (no Postmark API calls).
/// All send operations succeed without delivering anything.
/// Use for testing without email delivery or Postmark API.
#[derive(Clone, Debug, Default)]
pub struct InMemoryEmailsRepo {}

#[async_trait]
impl EmailsRepo for InMemoryEmailsRepo {
    async fn send_email(&self, _to: String, _subject: String, _email: String) -> Result<(), Error> {
        Ok(())
    }
}
