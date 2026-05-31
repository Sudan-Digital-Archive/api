# Overview

This is the API for the Sudan Digital Archive.

It is an axum web application that talks to a postgres database and
[browsertrix](https://browsertrix.com/).

## Local Development

You will need a local postgres database running. You can use the `docker-compose.local.yml` file for this. Install
[docker](https://www.docker.com/) and then run `docker compose -f docker-compose.local.yml up`.

## Running the Application

Copy `.env.example` to `.env` and fill in the required environment variables. Then:

```shell
export $(cat .env | xargs)
cargo run
```

For full documentation of all environment variables, see `.env.example`.

Once the application is running, you can access swagger docs at `localhost:port/sda-api/docs`. The `sda-api` prefix is
there since it gets deployed to this prefix on Digital Ocean, however note that you can toggle to a local server in
Swagger so the requests go through without the prefix, which is required for local development.

## Local Development Without External Dependencies

For development without real Browsertrix, S3, or Postmark credentials, you can use in-memory mock implementations:

```shell
MOCK_BROWSERTRIX=true
MOCK_S3=true
MOCK_POSTMARK=true
MOCK_AUTH=true
MOCK_DB=true
```

When using mocks, only the PostgreSQL database is required (via docker-compose.local.yml).

You can also disable rate limiting and tracing for cleaner local development logs:

```shell
ENABLE_RATE_LIMITING=false
ENABLE_TRACING=false
```

## Creating a Development Session

For testing without the email-based auth flow, use the `create_dev_session.sh` script to create a user and session directly in the database.

With docker-compose running:

```bash
docker exec sudan-digital-archive-api-db-1 /create_dev_session.sh dev@example.com
```

This will create a user and session, then output URLs for testing the API.

## Migrations

To run migrations:

```shell
export DATABASE_URL="postgresql://archivist:test@localhost/sudan_archives"
cd migration
cargo run -- up
```

## Database

It's pretty useful to generate entities with sea orm. That way you
get a rust model for exactly what is in your database. After running
migrations, to generate entities:
```shell
cargo run -- generate entity -u $DATABASE_URL -o entity/src
```

The code generation typically doesn't work with the layout of the app - it writes
stuff into `mod.rs` not `lib.rs` so I would focus instead on using it just for
modelling what's in the database, where it is perfect.

## Dockerfile

To test the Dockerfile, install [docker](https://www.docker.com/) and then run `docker build .`.

## Testing

Just run `export JWT_SECRET="some string" && cargo test`. Note that clippy and tests run in CI on pull and merge
to main. So, both need to pass before releasing code.

Note that at the time of writing, there are no integration tests - only unit.
You therefore should manually test anything that involves I/O to
external resources e.g. database since none of that functionality
will run in tests.

## Deployment

Merging to main triggers a push of the container image to Digital Ocean registry.
This overwrites the most recent `latest` tag and will automatically trigger a
redeploy of the application to app platform.