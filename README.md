# Secure Account FastAPI

An educational secure account management system built with FastAPI, async SQLAlchemy 2.0, SQLite/aiosqlite, Argon2id,
TOTP MFA, signed CAPTCHA, one-time tokens, secure sessions, brute-force protection, audit logs, OAuth, and SMTP email.

## Requirements

- [Python](https://www.python.org/) 3.11 or newer
- [uv](https://docs.astral.sh/uv/)

## Run locally

```bash
uv sync
cp .env.example .env
uv run uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000/>.

For a normal local run without auto-reload, use the project CLI command:

```bash
uv run secure-account
```

The database (`security.db`) and local email outbox (`.local_mail.json`) are created automatically. A default
administrator is seeded on startup:

```text
Email:    admin@example.com
Password: Admin!2026#Secure
```

These credentials are intended only for local demonstration. Change
`ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `SECRET_KEY` before using the
application outside a demo environment. Enable `COOKIE_SECURE=true` and use
HTTPS in production.

## Main features

- Registration with a password policy:
    - at least 8 characters;
    - uppercase and lowercase letters;
    - a digit;
    - a special character;
    - common-password detection;
    - client-side strength indicator: Weak, Medium, Strong.
- Argon2id password hashing.
- Cloudflare Turnstile CAPTCHA with server-side Siteverify validation for web
  registration and login verification.
- Signed mathematical CAPTCHA with an expiration time as a local/API fallback
  when Turnstile is disabled.
- One-time account activation links with a 24-hour lifetime.
- DB-backed HTTP-only sessions with logout invalidation.
- Five failed login attempts trigger a 15-minute temporary lock.
- Manual administrator blocking and unblocking.
- Role-based access control with separate `user` and `admin` roles.
- Audit logs with email, action, IP filtering, and failed-login counts.
- TOTP MFA with QR code generation, confirmation, display, and disable actions.
- Two-step web login: credentials first, then CAPTCHA and MFA only when enabled.
- Real Google OpenID Connect and GitHub OAuth Authorization Code login.
- Password reset links with one-time 15-minute tokens.
- Password changes from the profile after verifying the current password.
- Revocation of other active sessions after a password change or reset.
- Responsive Jinja2/Vanilla JS web interface.

## Web pages

| Page                      | URL                         |
|---------------------------|-----------------------------|
| Home                      | `/`                         |
| Sign in                   | `/login`                    |
| Registration              | `/register`                 |
| Profile                   | `/profile`                  |
| Administration            | `/admin`                    |
| Forgot password           | `/forgot-password`          |
| Reset password            | `/reset-password?token=...` |
| Swagger API documentation | `/docs`                     |

## API

The REST API uses the `/api/v1` prefix. Main endpoints include:

```text
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/captcha
POST /api/v1/auth/forgot-password
POST /api/v1/auth/reset-password
GET  /api/v1/users/me
POST /api/v1/users/me/password
POST /api/v1/users/me/totp/setup
POST /api/v1/users/me/totp/confirm
DELETE /api/v1/users/me/totp
GET  /api/v1/admin/users
GET  /api/v1/admin/audit
```

Audit filters can be combined:

```text
/api/v1/admin/audit?email=user@example.com&action=login_failed&ip=127.0.0.1
```

The API endpoint `POST /api/v1/users/me/password` requires the current
password, a new password, and the same password policy used during
registration.

## Project structure

```text
app/
├── api/
│   ├── deps.py
│   └── v1/
│       ├── auth.py
│       ├── users.py
│       ├── admin.py
│       └── captcha.py
├── core/
│   ├── config.py
│   ├── security.py
│   └── password_policy.py
├── db/
├── models/
├── schemas/
├── services/
├── templates/
└── main.py
```

Routes are implemented in `api`, application configuration and security
helpers are in `core`, SQLAlchemy entities are in `models`, Pydantic request
and response types are in `schemas`, and integrations such as email, CAPTCHA,
and TOTP are in `services`.

## Google and GitHub OAuth

Set credentials in `.env`:

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
OAUTH_REDIRECT_BASE_URL=http://127.0.0.1:8000
```

Register these callback URLs with the providers:

```text
http://127.0.0.1:8000/auth/oauth/google/callback
http://127.0.0.1:8000/auth/oauth/github/callback
```

Empty credentials do not enable a mock login; the application returns a clear configuration error.

OAuth requests use a signed `state` value with a 10-minute lifetime. It
contains the selected provider, a random nonce, and an expiration timestamp.
The callback verifies the HMAC signature, provider, expiration, and the
browser cookie when that cookie is available. This protects the authorization
callback from OAuth CSRF and login CSRF attacks.

The callback URLs must match the provider configuration exactly. In
particular, `127.0.0.1` and `localhost` are different hostnames:

```text
Google:
http://127.0.0.1:8000/auth/oauth/google/callback

GitHub:
http://127.0.0.1:8000/auth/oauth/github/callback
```

## Cloudflare Turnstile CAPTCHA

Create a Turnstile widget in the [Cloudflare dashboard](https://dash.cloudflare.com/):

1. Open **Turnstile** and create a widget.
2. Add the hostname used by the application, for example `127.0.0.1`.
3. Copy the site key and secret key.
4. Configure `.env`:

```env
CLOUDFLARE_TURNSTILE_ENABLED=true
CLOUDFLARE_TURNSTILE_SITE_KEY=your_site_key
CLOUDFLARE_TURNSTILE_SECRET_KEY=your_secret_key
```

The backend validates every token with Cloudflare's `siteverify` endpoint;
frontend success alone is never trusted. When Turnstile is disabled, the
signed local mathematical CAPTCHA remains available for local development and
API demos. Keep the secret key only in `.env`; it must never be exposed in
templates or committed to Git.

## Real email delivery through Gmail SMTP

By default, messages are printed to the console and written to
`.local_mail.json`. To send real activation and password-reset emails, enable
SMTP. Gmail with an App Password is used below as an example, but any SMTP
provider supporting STARTTLS or SMTPS can be configured:

```env
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your.account@gmail.com
SMTP_PASSWORD=your_16_character_app_password
SMTP_FROM_EMAIL=your.account@gmail.com
SMTP_FROM_NAME=Secure Account
SMTP_STARTTLS=true
```

Use a Google App Password, not the normal Gmail account password. Enable two-step verification first. Keep `.env`
private and restart the application after changing it. The local outbox is
intended for demonstrations and should not be treated as production email
storage.

## Session security

Sessions are stored in the database as SHA-256 digests of randomly generated
tokens. The raw token is sent only in an HTTP-only cookie, so browser
JavaScript cannot read it. Logout revokes the current session. Changing or
resetting a password revokes the user's other active sessions. In production,
set `COOKIE_SECURE=true` and serve the application over HTTPS.

## Production considerations

This project is designed for an educational laboratory and local
demonstration. Before production use:

- replace SQLite with a production database such as PostgreSQL;
- use HTTPS behind a properly configured reverse proxy;
- store `SECRET_KEY`, OAuth credentials, SMTP credentials, and Turnstile
  secret keys in a secret manager;
- change the seeded administrator credentials;
- configure IP-based rate limiting in addition to account lockout;
- configure secure cookie settings and review CSRF protection for every
  state-changing browser form;
- configure backups, monitoring, audit-log retention, and key rotation.

OAuth, SMTP, and Cloudflare Turnstile require credentials from their
respective providers. The application starts without them, but those
integrations cannot be demonstrated until their credentials and callback or
hostname settings are configured.
