# TaskAPI Backend

TaskAPI is a Node.js + Express + MongoDB API serving the TaskAPI platform. It handles user authentication, profiles, email/OTP verification, subscriptions (via Razorpay), and API key management for third-party developers.

The full machine-readable contract lives in [`openapi.yaml`](./openapi.yaml) — import it into Postman or Swagger UI to explore every endpoint with request/response schemas.

## Stack

- **Runtime:** Node.js (ESM, `"type": "module"`)
- **Framework:** Express 5
- **Database:** MongoDB via Mongoose 9, with PostgreSQL (Drizzle) + Redis for supporting subsystems
- **Validation:** Zod
- **Auth:** JWT access/refresh tokens, bcrypt password hashing, 2FA (TOTP via Speakeasy)
- **Queueing:** BullMQ + Redis
- **Rate limiting:** express-rate-limit + rate-limit-redis
- **Email/SMS:** Nodemailer, Twilio
- **Media:** Cloudinary (via Multer/streamifier)
- **Payments:** Razorpay

## Getting started

```bash
# install dependencies
npm install

# copy and fill in your environment variables
cp .env.example .env

# run the dev server (tsx watch)
npm run dev
```

The server listens on `http://localhost:3000` by default.

### Scripts

| Command                 | Description                                   |
| ----------------------- | --------------------------------------------- |
| `npm run dev`           | Start dev server with file watching            |
| `npm run start`         | Run the compiled output (`dist/server.js`)     |
| `npm run build`         | Compile TypeScript (`tsc`)                     |
| `npm run typecheck`     | Type-check without emitting                    |
| `npm run lint`          | Run ESLint over `.ts` files                    |
| `npm run clear`         | Reset the database (`dbresetScript.ts`)        |
| `npm run seed:admin`    | Seed an admin user                             |
| `npm run test:metrics`  | Exercise the metrics pipeline                  |
| `npm run test:bhash`    | bcrypt sanity check                            |

## REST API overview

All routes are prefixed by `/api/v1`. The API is grouped into four tag areas documented in `openapi.yaml`:

| Tag            | Description                                        |
| -------------- | -------------------------------------------------- |
| **Auth**       | Register, login/logout, account management, profile updates, forgot-password, OTP resend, token refresh |
| **General**    | Health check, contact-us, is-user, check-username  |
| **Subscription** | Create/upgrade order, verify payment, payment webhook |
| **Api Keys**   | Create, list, revoke, update, and delete API keys   |

### Key auth endpoints

- `POST /api/v1/auth/register` — new user registration (OTP email verification)
- `POST /api/v1/auth/login` — login; returns JWT cookies (`acToken` / refresh token)
- `POST /api/v1/auth/token/refresh` — rotate an expired access token
- `POST /api/v1/auth/logout` — end the current session

### API keys

`x-api-key` requests authenticate against a bcrypt-hashed key. The controller generates a plaintext key (prefixed `tk_`), the schema hashes it before persistence, and the middleware narrows lookup by the 8-char prefix then `bcrypt.compare`s for verification. Keys carry `scopes` (READ / WRITE / DELETE / ADMIN) and an optional allowed-IP whitelist.

For the full endpoint list — paths, parameters, request/response bodies — see [`openapi.yaml`](./openapi.yaml).

## Project structure

```
src/
├── app.ts / server.ts       # Express app + server bootstrap
├── configs/                 # app config, Redis init
├── constants.ts             # rate-limit windows, bcrypt salt rounds, Redis prefixes
├── controllers/             # General controllers (dashboard, etc.)
├── libs/                    # Shared libs (Zod schemas, BullMQ, Cloudinary, Twilio)
├── middlewares/             # Auth, token, error-handler, rate limiting, validation, metrics
├── modules/
│   ├── auth/                # Auth controllers, models, utils, routes
│   ├── clientauth/          # Client-facing auth for API-key consumers
│   ├── metrics/             # Raw events, rollups, aggregation workers
│   └── siteadmin/           # Admin/audit/metrics controllers
├── routes/                  # Route definitions
├── scripts/                 # Seed & admin scripts
├── services/                # Twilio, Redis OTP, Nodemailer
└── types/                   # MongoDB model & errors TypeScript types
```

## Contributing

1. Update the spec in `openapi.yaml` whenever you change routes.
2. Run `npm run typecheck` and `npm run lint` before opening a PR.