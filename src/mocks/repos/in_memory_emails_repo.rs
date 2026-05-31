use crate::repos::emails_repo::EmailsRepo;
use async_trait::async_trait;
use reqwest::Error;

#[derive(Clone, Debug, Default)]
pub struct InMemoryEmailsRepo {}

#[async_trait]
impl EmailsRepo for InMemoryEmailsRepo {
    async fn send_email(&self, _to: String, _subject: String, _email: String) -> Result<(), Error> {
        Ok(())
    }
}
