use crate::models::request::AuthorizeRequest;
use ::entity::api_key::ActiveModel as ApiKeyActiveModel;
use ::entity::api_key::Entity as ApiKey;
use ::entity::archive_user::Entity as ArchiveUser;
use ::entity::archive_user::Model as ArchiveUserModel;
use ::entity::sea_orm_active_enums::Role;
use ::entity::session::ActiveModel as SessionActiveModel;
use ::entity::session::Entity as Session;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use chrono::{Duration, NaiveDateTime, Utc};
use entity::{api_key, archive_user, session};
use rand::Rng;
use sea_orm::{ActiveModelTrait, ActiveValue};
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info};
use uuid::Uuid;

/// Response containing user email and role from API key verification.
///
/// This struct is returned when an API key is successfully verified and contains
/// the associated user's email address and their role in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyUserInfo {
    /// The email address of the user associated with the verified API key
    pub email: String,
    /// The role of the user (e.g., researcher, admin)
    pub role: Role,
}

/// Database-backed implementation of authentication operations.
///
/// This struct manages all authentication-related database operations including
/// user lookup, session management, and API key operations.
#[derive(Debug, Clone, Default)]
pub struct DBAuthRepo {
    /// Database connection for executing queries
    pub db_session: DatabaseConnection,
    /// Session expiration time in hours
    pub expiry_hours: i64,
}

/// Trait defining the interface for authentication repository operations.
///
/// This trait provides an abstraction for authentication-related database operations,
/// allowing for different implementations (e.g., mock implementations for testing).
#[async_trait]
pub trait AuthRepo: Send + Sync {
    /// Retrieves a user ID by their email address.
    ///
    /// # Arguments
    /// * `email` - The email address to search for
    ///
    /// # Returns
    /// Returns `Ok(Some(user_id))` if an active user with the email exists,
    /// `Ok(None)` if no user is found, or `Err` if a database error occurs.
    async fn get_user_by_email(&self, email: String) -> Result<Option<Uuid>, DbErr>;

    /// Creates a new session for a user.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to create a session for
    ///
    /// # Returns
    /// Returns `Ok(session_id)` containing the newly created session ID, or `Err` on database failure.
    async fn create_session(&self, user_id: Uuid) -> Result<Uuid, DbErr>;

    /// Deletes all expired sessions from the database.
    ///
    /// This function should be called periodically (e.g., via a background task) to clean up
    /// stale session records. It logs success or errors but does not return a result.
    async fn delete_expired_sessions(&self);

    /// Retrieves the expiry time of a session if it exists and is still valid.
    ///
    /// # Arguments
    /// * `authorize_request` - Contains the user ID and session ID to look up
    ///
    /// # Returns
    /// Returns `Ok(Some(expiry_time))` if a valid, non-expired session is found,
    /// `Ok(None)` if no matching session is found, or `Err` on database failure.
    async fn get_session_expiry(
        &self,
        authorize_request: AuthorizeRequest,
    ) -> Result<Option<NaiveDateTime>, DbErr>;

    /// Retrieves user information by their user ID.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to retrieve
    ///
    /// # Returns
    /// Returns `Ok(Some(user))` if an active user with the given ID exists,
    /// `Ok(None)` if no user is found, or `Err` on database failure.
    async fn get_one(&self, user_id: Uuid) -> Result<Option<ArchiveUserModel>, DbErr>;

    /// Creates a new API key for a user.
    ///
    /// This function generates a cryptographically secure random secret, hashes it with SHA256,
    /// stores the hash in the database, and returns the original secret to the user (encoded in base64).
    /// The API key is set to expire after 90 days by default.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to create an API key for
    ///
    /// # Returns
    /// Returns `Ok(api_key_secret)` containing the base64-URL encoded secret that should be
    /// provided to the user, or `Err` on database failure.
    async fn create_api_key_for_user(&self, user_id: Uuid) -> Result<String, DbErr>;

    /// Verifies an API key and retrieves associated user information.
    ///
    /// This function decodes the API key, hashes it, looks it up in the database,
    /// and verifies that it is not revoked and has not expired.
    ///
    /// # Arguments
    /// * `api_key` - The API key secret to verify
    ///
    /// # Returns
    /// Returns `Ok(Some(user_info))` if the API key is valid, `Ok(None)` if the key is invalid,
    /// revoked, or expired, or `Err` on database failure.
    async fn verify_api_key(&self, api_key: String) -> Result<Option<ApiKeyUserInfo>, DbErr>;

    /// Deletes all expired API keys from the database.
    ///
    /// This function should be called periodically (e.g., via a background task) to clean up
    /// expired API key records. It logs success or errors but does not return a result.
    async fn delete_expired_api_keys(&self);

    /// Creates a new user in the database.
    ///
    /// # Arguments
    /// * `email` - The email address of the new user
    /// * `role` - The role to assign to the user
    /// * `is_active` - Whether the user account is active
    ///
    /// # Returns
    /// Returns `Ok(user)` containing the newly created user, or `Err` if a database error occurs
    /// (e.g., unique constraint violation on email).
    async fn create_user(
        &self,
        email: String,
        role: Role,
        is_active: bool,
    ) -> Result<ArchiveUserModel, DbErr>;

    /// Updates an existing user's role and active status.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to update
    /// * `role` - The new role to assign
    /// * `is_active` - The new active status
    ///
    /// # Returns
    /// Returns `Ok(Some(user))` containing the updated user if found,
    /// `Ok(None)` if no user exists with the given ID, or `Err` on database failure.
    async fn update_user(
        &self,
        user_id: Uuid,
        role: Role,
        is_active: bool,
    ) -> Result<Option<ArchiveUserModel>, DbErr>;

    /// Retrieves a user by their ID (including inactive users).
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to retrieve
    ///
    /// # Returns
    /// Returns `Ok(Some(user))` if a user with the given ID exists (regardless of active status),
    /// `Ok(None)` if no user is found, or `Err` on database failure.
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<ArchiveUserModel>, DbErr>;

    /// Lists users with optional email filtering and pagination.
    ///
    /// # Arguments
    /// * `page` - The page number (0-indexed)
    /// * `per_page` - Number of items per page
    /// * `email_filter` - Optional email substring to filter by
    ///
    /// # Returns
    /// Returns `Ok((users, num_pages))` containing the list of users and total page count,
    /// or `Err` on database failure.
    async fn list_users(
        &self,
        page: u64,
        per_page: u64,
        email_filter: Option<String>,
    ) -> Result<(Vec<ArchiveUserModel>, u64), DbErr>;

    /// Deletes a user and all associated sessions and API keys.
    ///
    /// This is a hard delete that cascades to related entities.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to delete
    ///
    /// # Returns
    /// Returns `Ok(Some(()))` if the user was found and deleted,
    /// `Ok(None)` if no user exists with the given ID, or `Err` on database failure.
    async fn delete_user(&self, user_id: Uuid) -> Result<Option<()>, DbErr>;

    /// Revokes an API key by its hash, but only if it belongs to the specified user.
    ///
    /// # Arguments
    /// * `key_hash` - The SHA256 hash of the API key to revoke
    /// * `user_id` - The ID of the user the API key must belong to
    ///
    /// # Returns
    /// Returns `Ok(Some(()))` if the API key was found and revoked,
    /// `Ok(None)` if no API key exists with the given hash or it doesn't belong to the user,
    /// or `Err` on database failure.
    async fn revoke_api_key(&self, key_hash: String, user_id: Uuid) -> Result<Option<()>, DbErr>;
}

#[async_trait]
impl AuthRepo for DBAuthRepo {
    /// Retrieves a user ID by their email address.
    ///
    /// Queries the database for an active user with the specified email.
    ///
    /// # Arguments
    /// * `email` - The email address to search for
    ///
    /// # Returns
    /// Returns `Ok(Some(user_id))` if found, `Ok(None)` if not found or inactive.
    async fn get_user_by_email(&self, email: String) -> Result<Option<Uuid>, DbErr> {
        let user = ArchiveUser::find()
            .filter(archive_user::Column::Email.eq(email))
            .filter(archive_user::Column::IsActive.eq(true))
            .one(&self.db_session)
            .await?;
        match user {
            Some(user) => Ok(Some(user.id)),
            None => Ok(None),
        }
    }

    /// Creates a new session for a user with an expiration time.
    ///
    /// Generates a new session ID and sets its expiration based on the configured `expiry_hours`.
    ///
    /// # Arguments
    /// * `user_id` - The user to create a session for
    ///
    /// # Returns
    /// Returns the newly created session ID.
    async fn create_session(&self, user_id: Uuid) -> Result<Uuid, DbErr> {
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let expiry_time = now + Duration::hours(self.expiry_hours);
        let session = SessionActiveModel {
            id: ActiveValue::Set(session_id),
            expiry_time: ActiveValue::Set(expiry_time.naive_utc()),
            user_id: ActiveValue::Set(user_id),
        };
        let session = session.insert(&self.db_session).await?;
        Ok(session.id)
    }

    /// Deletes all sessions that have expired from the database.
    ///
    /// Finds all sessions where the expiry time is less than or equal to the current time
    /// and removes them. Logs the result or any errors that occur.
    async fn delete_expired_sessions(&self) {
        let now = Utc::now().naive_utc();
        let delete_result = Session::delete_many()
            .filter(session::Column::ExpiryTime.lte(now))
            .exec(&self.db_session)
            .await;
        match delete_result {
            Ok(_) => {
                info!("Successfully deleted expired sessions.");
            }
            Err(err) => {
                error!(%err, "Error deleting expired sessions");
            }
        }
    }

    /// Retrieves the expiry time of a valid session.
    ///
    /// Verifies that a session exists for the given user, has not expired, and returns its expiry time.
    ///
    /// # Arguments
    /// * `authorize_request` - Contains the user ID and session ID
    ///
    /// # Returns
    /// Returns the expiry time if valid, or `None` if session not found or expired.
    async fn get_session_expiry(
        &self,
        authorize_request: AuthorizeRequest,
    ) -> Result<Option<NaiveDateTime>, DbErr> {
        let session = Session::find()
            .filter(session::Column::UserId.eq(authorize_request.user_id))
            .filter(session::Column::Id.eq(authorize_request.session_id))
            .filter(session::Column::ExpiryTime.gt(Utc::now().naive_utc()))
            .one(&self.db_session)
            .await?;
        match session {
            Some(found_session) => Ok(Some(found_session.expiry_time)),
            None => Ok(None),
        }
    }

    /// Retrieves a user record by their ID.
    ///
    /// Returns the full user model for an active user with the specified ID.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to retrieve
    ///
    /// # Returns
    /// Returns the user model if found and active, or `None` if not found or inactive.
    async fn get_one(&self, user_id: Uuid) -> Result<Option<ArchiveUserModel>, DbErr> {
        let user = ArchiveUser::find()
            .filter(archive_user::Column::Id.eq(user_id))
            .filter(archive_user::Column::IsActive.eq(true))
            .one(&self.db_session)
            .await?;
        match user {
            Some(user) => Ok(Some(user)),
            None => Ok(None),
        }
    }

    /// Creates a new API key for a user with a 90-day expiration.
    ///
    /// Generates a cryptographically secure 32-byte random secret, hashes it using SHA256,
    /// stores the hash in the database, and returns the original secret (base64-URL encoded)
    /// to the user. The user should securely store this returned value.
    ///
    /// # Arguments
    /// * `user_id` - The user to create an API key for
    ///
    /// # Returns
    /// Returns the base64-URL encoded API key secret that should be provided to the user.
    async fn create_api_key_for_user(&self, user_id: Uuid) -> Result<String, DbErr> {
        let mut secret_bytes = [0u8; 32];
        {
            let mut rng = rand::thread_rng();
            rng.fill(&mut secret_bytes);
        }

        let mut hasher = Sha256::new();
        hasher.update(secret_bytes);
        let key_hash = hasher.finalize();
        let key_hash_hex = format!("{key_hash:x}");

        let api_key_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + Duration::days(90);

        let api_key = ApiKeyActiveModel {
            id: ActiveValue::Set(api_key_id),
            user_id: ActiveValue::Set(user_id),
            key_hash: ActiveValue::Set(key_hash_hex),
            created_at: ActiveValue::Set(now.naive_utc()),
            expires_at: ActiveValue::Set(expires_at.naive_utc()),
            is_revoked: ActiveValue::Set(false),
        };

        api_key.insert(&self.db_session).await?;

        let encoded_secret = URL_SAFE.encode(secret_bytes);
        Ok(encoded_secret)
    }

    /// Verifies an API key and retrieves the associated user's information.
    ///
    /// Decodes the provided API key, hashes it, and looks it up in the database.
    /// Returns user information only if the key exists, is not revoked, and has not expired.
    ///
    /// # Arguments
    /// * `api_key` - The API key secret to verify (base64-URL encoded)
    ///
    /// # Returns
    /// Returns user information (email and role) if the key is valid, or `None` if the key
    /// is invalid, malformed, revoked, or expired.
    async fn verify_api_key(&self, api_key: String) -> Result<Option<ApiKeyUserInfo>, DbErr> {
        let secret_bytes = match URL_SAFE.decode(&api_key) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(None),
        };

        let mut hasher = Sha256::new();
        hasher.update(secret_bytes);
        let key_hash = hasher.finalize();
        let key_hash_hex = format!("{key_hash:x}");
        let api_key_record = ApiKey::find()
            .filter(api_key::Column::KeyHash.eq(key_hash_hex))
            .filter(api_key::Column::IsRevoked.eq(false))
            .filter(api_key::Column::ExpiresAt.gt(Utc::now().naive_utc()))
            .one(&self.db_session)
            .await?;

        match api_key_record {
            Some(key_record) => {
                let user = ArchiveUser::find()
                    .filter(archive_user::Column::Id.eq(key_record.user_id))
                    .filter(archive_user::Column::IsActive.eq(true))
                    .one(&self.db_session)
                    .await?;

                match user {
                    Some(user) => Ok(Some(ApiKeyUserInfo {
                        email: user.email,
                        role: user.role,
                    })),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// Deletes all expired API keys from the database.
    ///
    /// Finds all API keys where the expiration time has passed and removes them.
    /// Logs the result or any errors that occur. Useful as a periodic cleanup task.
    async fn delete_expired_api_keys(&self) {
        let now = Utc::now().naive_utc();
        let delete_result = ApiKey::delete_many()
            .filter(api_key::Column::ExpiresAt.lte(now))
            .exec(&self.db_session)
            .await;

        match delete_result {
            Ok(_) => {
                info!("Successfully deleted expired API keys.");
            }
            Err(err) => {
                error!(%err, "Error deleting expired API keys");
            }
        }
    }

    /// Creates a new user in the database.
    async fn create_user(
        &self,
        email: String,
        role: Role,
        is_active: bool,
    ) -> Result<ArchiveUserModel, DbErr> {
        let user_id = Uuid::new_v4();
        let user = archive_user::ActiveModel {
            id: ActiveValue::Set(user_id),
            email: ActiveValue::Set(email),
            role: ActiveValue::Set(role),
            is_active: ActiveValue::Set(is_active),
        };
        user.insert(&self.db_session).await
    }

    /// Updates an existing user's role and active status.
    async fn update_user(
        &self,
        user_id: Uuid,
        role: Role,
        is_active: bool,
    ) -> Result<Option<ArchiveUserModel>, DbErr> {
        let user = ArchiveUser::find_by_id(user_id)
            .one(&self.db_session)
            .await?;

        match user {
            Some(existing_user) => {
                let mut user_active_model: archive_user::ActiveModel = existing_user.into();
                user_active_model.role = ActiveValue::Set(role);
                user_active_model.is_active = ActiveValue::Set(is_active);
                let updated_user = user_active_model.update(&self.db_session).await?;
                Ok(Some(updated_user))
            }
            None => Ok(None),
        }
    }

    /// Retrieves a user by their ID (including inactive users).
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<ArchiveUserModel>, DbErr> {
        ArchiveUser::find_by_id(user_id).one(&self.db_session).await
    }

    /// Lists users with optional email filtering and pagination.
    async fn list_users(
        &self,
        page: u64,
        per_page: u64,
        email_filter: Option<String>,
    ) -> Result<(Vec<ArchiveUserModel>, u64), DbErr> {
        let mut query = ArchiveUser::find();

        // Apply email filter if provided
        if let Some(filter) = email_filter {
            query = query.filter(archive_user::Column::Email.contains(filter));
        }

        // Get total count for pagination
        let total_count = query.clone().count(&self.db_session).await?;
        let num_pages = (total_count + per_page - 1).div_ceil(per_page);
        // Fetch the page
        let users = query
            .order_by_asc(archive_user::Column::Email)
            .offset(page * per_page)
            .limit(per_page)
            .all(&self.db_session)
            .await?;

        Ok((users, num_pages))
    }

    /// Deletes a user and all associated sessions and API keys.
    async fn delete_user(&self, user_id: Uuid) -> Result<Option<()>, DbErr> {
        // Check if user exists first
        let user = ArchiveUser::find_by_id(user_id)
            .one(&self.db_session)
            .await?;

        if user.is_none() {
            return Ok(None);
        }

        // Delete associated sessions first
        Session::delete_many()
            .filter(session::Column::UserId.eq(user_id))
            .exec(&self.db_session)
            .await?;

        // Delete associated API keys
        ApiKey::delete_many()
            .filter(api_key::Column::UserId.eq(user_id))
            .exec(&self.db_session)
            .await?;

        // Delete the user
        ArchiveUser::delete_by_id(user_id)
            .exec(&self.db_session)
            .await?;

        Ok(Some(()))
    }

    /// Revokes an API key by its hash, but only if it belongs to the specified user.
    async fn revoke_api_key(&self, key_hash: String, user_id: Uuid) -> Result<Option<()>, DbErr> {
        // Find the API key by hash and verify it belongs to the user
        let api_key = ApiKey::find()
            .filter(api_key::Column::KeyHash.eq(key_hash))
            .filter(api_key::Column::UserId.eq(user_id))
            .one(&self.db_session)
            .await?;

        match api_key {
            Some(key) => {
                let mut active_key: api_key::ActiveModel = key.into();
                active_key.is_revoked = ActiveValue::Set(true);
                active_key.update(&self.db_session).await?;
                Ok(Some(()))
            }
            None => Ok(None),
        }
    }
}
