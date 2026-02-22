# Sudan Digital Archive API - Agent Guidelines

This file contains guidelines for agentic coding agents working on this Rust/Axum API codebase.

## Essential Commands

### Development Workflow
- **Always run `cargo check`** after making changes to ensure compilation
- **Always run `export JWT_SECRET="test" && cargo test`** before considering work complete
- Don't assume work is done until code compiles AND tests pass

### Build/Lint/Test Commands
```shell
# Check all workspace crates compile
cargo check --workspace

# Run all tests (requires JWT_SECRET)
export JWT_SECRET="test" && cargo test

# Run a specific test
export JWT_SECRET="test" && cargo test test_name

# Linting (used in CI)
cargo clippy -- -D warnings

# Formatting check
cargo fmt -- --check

# Apply formatting
cargo fmt
```

### Database Operations
```shell
# Start local database
docker compose -f docker-compose.local.yml up

# Run migrations
export DATABASE_URL="postgresql://archivist:test@localhost/sudan_archives"
cd migration
cargo run -- up

# Generate entities (after migrations)
cargo run -- generate entity -u $DATABASE_URL -o entity/src
```

### Running the Application
```shell
export $(cat .env | xargs)
cargo run
```

## Code Style Guidelines

### Imports and Module Organization
- Use standard Rust module organization (`mod.rs` for directories)
- Import external crates first, then local modules
- Group related imports together
- Prefer `use crate::` for local modules

### Error Handling
- Use custom error types (see `src/models/auth.rs:15` for `AuthError` pattern)
- Implement `IntoResponse` for error types to integrate with Axum
- Return `Result<T, Error>` from fallible functions
- Handle external service errors gracefully with proper error messages

### Types and Naming
- Use `snake_case` for variables and functions
- Use `PascalCase` for types and structs
- Use `SCREAMING_SNAKE_CASE` for constants
- Be descriptive with variable names
- Use type aliases where appropriate for complex types

### Testing
- Unit tests use in-memory repositories to avoid I/O operations
- Test files in the same module or separate `#[cfg(test)]` modules
- Use `pretty_assertions` for better test output (already in dev-dependencies)
- Mock external services (see `src/test_tools.rs`)
- Manually test I/O operations since no integration tests exist

### API Documentation
- Use `utoipa` for OpenAPI documentation
- Add `#[derive(ToSchema, ToResponse)]` to relevant types
- Document API routes with utoipa macros
- Access Swagger UI at `/sda-api/docs` when running

### Database Patterns
- Use sea-orm as the ORM
- Repository pattern for data access (see `src/repos/`)
- Service layer for business logic (see `src/services/`)
- Use transactions for multi-table operations
- Handle database errors in repository layer

### Configuration
- Environment-based configuration via `.env` file
- See `README.MD` for required environment variables
- Configuration struct in `src/config.rs`
- Never commit secrets or `.env` files

### Security
- JWT-based authentication via cookies
- Use `jsonwebtoken` crate for token handling
- Rate limiting with `tower_governor`
- CORS configuration in app factory
- Validate input with `validator` crate

### Performance Considerations
- Use async/await throughout the application
- Database operations should be async
- File uploads use streaming to handle large files
- Connection pooling via sea-orm

## Project Structure

```
src/
├── main.rs           # Application entry point
├── app_factory.rs    # Axum app configuration and middleware
├── config.rs         # Configuration management
├── auth.rs           # JWT authentication logic
├── models/           # Data models and request/response types
├── routes/           # API route handlers
├── services/         # Business logic layer
├── repos/            # Data access layer
└── test_tools.rs     # Testing utilities (cfg test)
```

## CI/CD Requirements

The CI pipeline runs on every PR and merge to main:
- `cargo fmt -- --check` (formatting)
- `cargo clippy -- -D warnings` (linting)
- `cargo test` (with JWT_SECRET="testsecret")

All must pass before code can be merged to main.

## External Integrations

- **Database**: PostgreSQL via sea-orm
- **File Storage**: DigitalOcean Spaces (S3-compatible)
- **Web Crawling**: Browsertrix API
- **Email**: Postmark API
- **Authentication**: JWT tokens in cookies

## Notes for Agents

- This is a high-quality codebase with established patterns
- Follow existing conventions rather than introducing new patterns
- The codebase uses workspace structure with `entity` and `migration` sub-crates
- Database schema changes require both migration and entity updates
- Manual testing is required for I/O operations since no integration tests exist
- The application follows RESTful API design principles