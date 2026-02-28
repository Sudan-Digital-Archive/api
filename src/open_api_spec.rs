use crate::models::request::{
    AccessionPagination, AccessionPaginationWithPrivate, AuthorizeRequest, CollectionLangParam,
    CollectionPagination, CollectionPaginationWithPrivate, CreateAccessionRequest,
    CreateAccessionRequestRaw, CreateCollectionRequest, CreateCreatorRequest,
    CreateLocationRequest, CreateSubjectRequest, CreateUserRequest, CreatorLangParam,
    CreatorPagination, DeleteCreatorRequest, DeleteLocationRequest, DeleteSubjectRequest,
    LocationLangParam, LocationPagination, LoginRequest, RevokeApiKeyRequest, SubjectLangParam,
    SubjectPagination, UpdateAccessionRequest, UpdateCollectionRequest, UpdateCreatorRequest,
    UpdateLocationRequest, UpdateSubjectRequest, UpdateUserRequest, UserPagination,
};
use crate::models::response::{
    CollectionResponse, CreateApiKeyResponse, CreatorResponse, GetOneAccessionResponse,
    ListAccessionsResponse, ListCollectionsResponse, ListCreatorsResponse, ListLocationsResponse,
    ListSubjectsArResponse, ListSubjectsEnResponse, ListUsersResponse, LocationResponse,
    SubjectResponse, UserResponse,
};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "jwt_cookie_auth",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("jwt"))),
        );
        components.add_security_scheme(
            "api_key_auth",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Api-Key"))),
        );
    }
}

/// OpenAPI specification for the Sudan Digital Archive API
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::health::healthcheck,
        crate::routes::accessions::create_accession_crawl,
        crate::routes::accessions::create_accession_raw,
        crate::routes::accessions::get_one_accession,
        crate::routes::accessions::get_one_private_accession,
        crate::routes::accessions::list_accessions,
        crate::routes::accessions::list_accessions_private,
        crate::routes::accessions::delete_accession,
        crate::routes::accessions::update_accession,
        crate::routes::auth::login,
        crate::routes::auth::authorize,
        crate::routes::auth::verify,
        crate::routes::auth::create_api_key,
        crate::routes::auth::revoke_api_key,
        crate::routes::auth::create_user,
        crate::routes::auth::list_users,
        crate::routes::auth::get_user,
        crate::routes::auth::update_user,
        crate::routes::auth::delete_user,
        crate::routes::subjects::create_subject,
        crate::routes::subjects::list_subjects,
        crate::routes::subjects::get_one_subject,
        crate::routes::subjects::delete_subject,
        crate::routes::subjects::update_subject,
        crate::routes::locations::create_location,
        crate::routes::locations::list_locations,
        crate::routes::locations::get_one_location,
        crate::routes::locations::delete_location,
        crate::routes::locations::update_location,
        crate::routes::creators::create_creator,
        crate::routes::creators::list_creators,
        crate::routes::creators::get_one_creator,
        crate::routes::creators::delete_creator,
        crate::routes::creators::update_creator,
        crate::routes::collections::list_collections,
        crate::routes::collections::list_collections_private,
        crate::routes::collections::get_one_collection,
        crate::routes::collections::create_collection,
        crate::routes::collections::update_collection,
        crate::routes::collections::delete_collection
    ),
    components(
        schemas(
            AccessionPagination,
            AccessionPaginationWithPrivate,
            CreateAccessionRequest,
            CreateAccessionRequestRaw,
            UpdateAccessionRequest,
            GetOneAccessionResponse,
            ListAccessionsResponse,
            LoginRequest,
            AuthorizeRequest,
            CreateApiKeyResponse,
            CreateSubjectRequest,
            UpdateSubjectRequest,
            DeleteSubjectRequest,
            SubjectPagination,
            SubjectLangParam,
            SubjectResponse,
            ListSubjectsEnResponse,
            ListSubjectsArResponse,
            CreateLocationRequest,
            UpdateLocationRequest,
            DeleteLocationRequest,
            LocationPagination,
            LocationLangParam,
            LocationResponse,
            ListLocationsResponse,
            CreateCreatorRequest,
            UpdateCreatorRequest,
            DeleteCreatorRequest,
            CreatorPagination,
            CreatorLangParam,
            CreatorResponse,
            ListCreatorsResponse,
            CreateUserRequest,
            UpdateUserRequest,
            UserPagination,
            UserResponse,
            ListUsersResponse,
            RevokeApiKeyRequest,
            CollectionPagination,
            CollectionPaginationWithPrivate,
            CollectionLangParam,
            CreateCollectionRequest,
            UpdateCollectionRequest,
            CollectionResponse,
            ListCollectionsResponse
        )
    ),
    tags(
        (name = "Healthcheck", description = "Health check endpoints"),
        (name = "Accessions", description = "Accession management endpoints"),
        (name = "Auth", description = "User authentication endpoints"),
        (name = "Subjects", description = "Subject management endpoints"),
        (name = "Locations", description = "Location management endpoints"),
        (name = "Creators", description = "Creator management endpoints"),
        (name = "Collections", description = "Collection management endpoints")
    ),
    modifiers(&SecurityAddon),
    servers(
        // Deployed on Digital Ocean spaces which has a HTTP request config that slaps on this sda-api prefix
        (url = "/sda-api", description = "Production deployment with prefix"),
        (url = "/", description = "Local development without prefix")
    )
)]
pub struct ApiDoc;
