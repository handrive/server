# Handrive Server

Rust/Axum API backend for Handrive — a peer-to-peer file sharing application.

## Features

- JWT authentication with access/refresh tokens
- Google OAuth, Apple Sign In, and email OTP login
- NATS messaging for P2P sync
- PostgreSQL database with SQLx
- Rate limiting and security headers
- Docker deployment with auto-TLS via Caddy
- Dev environment support on the same droplet

## Data Storage

The server is purely an auth and credential provisioning service. It holds no files, messages, or sync data. NATS acts only as a signaling layer — file metadata and content are transferred directly between peers.

PostgreSQL contains three tables:

| Table | Data | Retention |
|-------|------|-----------|
| `users` | email, name, avatar URL, Google/Apple ID, metadata | Permanent until account deletion |
| `otp_codes` | email, 6-digit code, expiry, used flag | Ephemeral — 5 min TTL, background cleanup |
| `sessions` | user ID, hashed refresh token, expiry | Deleted on logout/token rotation, background cleanup |

## Requirements

- Rust 1.93+
- PostgreSQL 16+
- NATS 2.10+

## Development

```bash
# Clone the repository
git clone https://github.com/handrive/server.git
cd handriveapp-server

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Run the server
cargo run --package handrive-server
```

Migrations run automatically on startup via `sqlx::migrate!`.

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | Yes |
| `NATS_URL` | NATS server URL | Yes |
| `NATS_ACCOUNT_SIGNING_KEY` | NATS account seed (starts with SA) | Yes |
| `NATS_ACCOUNT_PUBLIC_KEY` | NATS account public key (starts with A) | Yes |
| `IDENTITY_SIGNING_KEY` | Ed25519 key for NATS message signing | No |
| `RESEND_API_KEY` | Resend API key for email OTP | Yes |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | Yes |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | Yes |
| `GOOGLE_REDIRECT_URI` | Google OAuth redirect URI | Yes |
| `CORS_ORIGINS` | Comma-separated allowed origins | No |
| `NATS_PUBLIC_URL` | Public NATS URL returned to clients | No |
| `TEST_MODE` | Return OTP codes in responses (dev only) | No |
| `APPLE_CLIENT_ID` | Apple Sign In client ID | No |
| `APPLE_TEAM_ID` | Apple Developer team ID | No |
| `APPLE_KEY_ID` | Apple Sign In key ID | No |
| `APPLE_PRIVATE_KEY_FILE` | Path to Apple private key (.pem) | No |
| `DEMO_EMAIL` | Demo account email for App Store review | No |
| `DEMO_OTP` | Demo account OTP code | No |
| `LOG_LEVEL` | Log level (default: info) | No |
| `LOG_DIR` | Log file directory (default: /var/log/handrive) | No |
| `LOG_RETENTION_DAYS` | Days to keep log files (default: 7) | No |
| `CLEANUP_INTERVAL_SECS` | Cleanup interval in seconds (default: 43200) | No |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check (DB + NATS) |
| `GET` | `/api/auth/status` | Check authentication status |
| `GET` | `/api/auth/google/url` | Get Google OAuth URL |
| `POST` | `/api/auth/google/callback` | Google OAuth callback |
| `GET` | `/api/auth/apple/url` | Get Apple Sign In URL |
| `POST` | `/api/auth/apple/callback` | Apple Sign In callback |
| `POST` | `/api/auth/otp/request` | Request email OTP |
| `POST` | `/api/auth/otp/verify` | Verify OTP and login |
| `POST` | `/api/auth/refresh` | Refresh access token |
| `POST` | `/api/auth/logout` | Logout (revoke refresh token) |
| `GET` | `/api/users/me` | Get current user profile |
| `PATCH` | `/api/users/me` | Update current user profile |
| `DELETE` | `/api/users/me` | Delete account (requires "DELETE" confirmation) |
| `GET` | `/api/users/search` | Search user by email |
| `POST` | `/api/users/lookup` | Batch lookup users by email list |
| `POST` | `/api/users/invite` | Invite user by email |
| `GET` | `/api/sessions` | List active sessions |
| `DELETE` | `/api/sessions/:id` | Revoke a session |
| `DELETE` | `/api/sessions` | Revoke all other sessions |
| `GET` | `/api/nats/credentials` | Get NATS JWT credentials |
| `GET` | `/auth/callback` | Desktop OAuth redirect (deep link) |
| `POST` | `/auth/apple/callback` | Desktop Apple OAuth redirect |

## NATS Security

NATS authentication uses two independent layers — one for connection access and one for message authenticity.

### Connection Auth (Decentralized JWTs)

The NATS server verifies client connections using Ed25519-signed JWTs. No shared secret is exchanged with NATS.

```
Login → Server signs user JWT with account signing key
      → Client receives credentials file (JWT + user seed)
      → Client connects to NATS
      → NATS verifies JWT signature against account public key
```

On each login, the server (`nats/jwt.rs`):

1. Generates a fresh Ed25519 user keypair via `nkeys`
2. Builds a JWT containing publish/subscribe permissions scoped to the user
3. Signs the JWT with the account signing key (`NATS_ACCOUNT_SIGNING_KEY`)
4. Returns a NATS credentials file (JWT + user seed) to the client

The NATS server validates the JWT signature using the account public key (`NATS_ACCOUNT_PUBLIC_KEY`) configured in `nats.conf` — no callback to the app server required.

**Permission scoping per user:**

| Action | Allowed subjects |
|--------|-----------------|
| Publish | `sync.>` |
| Subscribe | `sync.{user_id}.>` (own subjects only) |

### Message Auth (Identity Credentials)

A separate Ed25519 key (`IDENTITY_SIGNING_KEY`) signs identity credentials so peers can verify message senders without trusting the NATS broker.

The server (`auth/identity.rs`) signs the string `email|issued_at|expires_at` and returns the credential along with the server's public key. Clients attach this to NATS messages; receiving peers verify the signature to confirm the sender is authenticated.

Identity credentials expire with the access token (default 24 hours) and are refreshed via `/api/auth/refresh`.

### No Data Persistence

NATS is configured as pure pub/sub with no JetStream or storage enabled. Messages are delivered to connected subscribers in real-time and discarded — NATS holds no data. If a client is offline, it misses those messages.

## Production Deployment

### Architecture

```
Internet → Caddy (:443 HTTPS) → Server (:3001)
Internet → NATS (:4222 TLS)
Server   → NATS (internal, via Docker network alias)
```

### Deploy

```bash
docker compose -f docker-compose.prod.yml up -d
```

### GitHub Actions

The workflow (`.github/workflows/deploy.yml`) automates deployment via manual trigger (`workflow_dispatch`):

1. Creates DigitalOcean Droplet and managed PostgreSQL if needed
2. Configures TLS certificates via Caddy + Let's Encrypt
3. Builds and deploys with rolling restart

Required GitHub secrets:

| Secret | Description |
|--------|-------------|
| `DIGITALOCEAN_ACCESS_TOKEN` | DigitalOcean API token |
| `DROPLET_SSH_KEY` | SSH private key for droplet access |
| `JWT_SECRET` | JWT signing secret |
| `NATS_ACCOUNT_SIGNING_KEY` | NATS account seed |
| `NATS_ACCOUNT_PUBLIC_KEY` | NATS account public key |
| `IDENTITY_SIGNING_KEY` | Ed25519 key for NATS message signing |
| `GH_PAT` | GitHub PAT for cloning private repos |
| `RESEND_API_KEY` | Resend email API key |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `APPLE_CLIENT_ID` | Apple Sign In client ID |
| `APPLE_TEAM_ID` | Apple Developer team ID |
| `APPLE_KEY_ID` | Apple Sign In key ID |
| `APPLE_PRIVATE_KEY` | Apple private key contents |

## Dev Environment

A dev environment can run alongside production on the same droplet using a separate domain (e.g., `dev.handrive.ai`).

### Architecture

```
Internet → Caddy (:443)
             ├── api.handrive.ai  → server:3001      (prod)
             └── dev.handrive.ai  → server-dev:3001   (dev)

NATS prod: :4222 (TLS)
NATS dev:  :4223 (TLS)
```

### What's shared vs separate

| Component | Shared | Separate |
|-----------|--------|----------|
| Caddy (reverse proxy + TLS) | Shared | |
| cert-exporter | Shared | |
| Resend API key | Shared | |
| Server container | | Separate |
| NATS instance | | Separate (ports 4222 / 4223) |
| PostgreSQL database | Same server | `handrive` / `handrive_dev` |
| JWT secret | | Separate |
| NATS keys | | Separate |

### Setup

1. Add DNS A record: `dev.handrive.ai` → same droplet IP
2. Add GitHub secrets: `JWT_SECRET_DEV`, `NATS_ACCOUNT_SIGNING_KEY_DEV`, `NATS_ACCOUNT_PUBLIC_KEY_DEV`, `IDENTITY_SIGNING_KEY_DEV`
3. Push to `dev` branch — triggers `.github/workflows/deploy-dev.yml`

### Manual deploy

```bash
# Start dev services (requires prod stack running)
docker compose -f docker-compose.dev.yml --env-file .env.dev up -d
```

## License

AGPL-3.0
