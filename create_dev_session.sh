#!/bin/bash
# Usage: ./create_dev_session.sh [email]
# Creates a fake user session for local dev and outputs the URLs needed

DB_URL="postgresql://archivist:test@localhost/sudan_archives"
EMAIL="${1:-dev@example.com}"

# Generate UUIDs
USER_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
SESSION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

# Set expiry to 7 days from now
EXPIRY=$(date -v+7d -u +"%Y-%m-%d %H:%M:%S")

# Insert user and session
psql "$DB_URL" -c "
INSERT INTO archive_user (id, email, is_active, role) 
VALUES ('$USER_ID', '$EMAIL', true, 'admin')
ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id;
" 2>/dev/null || true

# Get actual user ID if it already existed
USER_ID=$(psql "$DB_URL" -t -c "SELECT id FROM archive_user WHERE email = '$EMAIL';" | xargs)

psql "$DB_URL" -c "
INSERT INTO session (id, expiry_time, user_id) 
VALUES ('$SESSION_ID', '$EXPIRY', '$USER_ID')
ON CONFLICT (id) DO UPDATE SET expiry_time = EXCLUDED.expiry_time;
"

FRONTEND_URL="http://localhost:5173/jwt-auth?sessionId=$SESSION_ID&userId=$USER_ID"
API_URL="http://localhost:5001/api/v1/auth/authorize"

echo "Session created!"
echo ""
echo "User ID:  $USER_ID"
echo "Session ID: $SESSION_ID"
echo ""
echo "Frontend URL:"
echo "$FRONTEND_URL"
echo ""
echo "Or test the API directly:"
echo "curl -X POST $API_URL \\
  -H 'Content-Type: application/json' \\
  -d '{\"session_id\": \"$SESSION_ID\", \"user_id\": \"$USER_ID\"}' \\
  -c cookies.txt"
