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

The database (`security.db`) and local email outbox (`.local_mail.json`) are created automatically. A default
administrator is seeded on startup:

```text
Email:    admin@example.com
Password: Admin!2026#Secure
```

Change the default secret key and administrator password before using the application outside a demo environment. Enable
`COOKIE_SECURE=true` and use HTTPS in production.

## Main features

- Registration with a password policy:
    - at least 8 characters;
    - uppercase and lowercase letters;
    - a digit;
    - a special character;
    - common-password detection;
    - client-side strength indicator: Weak, Medium, Strong.
- Argon2id password hashing.
- CAPTCHA with a signed HMAC token and expiration time.
- Cloudflare Turnstile CAPTCHA for web registration and login verification.
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

The backend validates every token with Cloudflare's `siteverify` endpoint. When Turnstile is disabled, the local
mathematical CAPTCHA remains available for local development and API demos.

## Real email delivery through Gmail SMTP

By default, messages are printed to the console and written to `.local_mail.json`. To send real activation and
password-reset emails, enable Gmail SMTP with a Google App Password:

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
private and restart Uvicorn after changing it.

## Demonstration scenarios

1. Register a user and solve the CAPTCHA.
2. Open the activation link from the console, local outbox, or email.
3. Sign in and open the profile.
4. Create and confirm TOTP MFA with Google Authenticator or Aegis.
5. Sign out and verify the second login step.
6. Submit five incorrect passwords and observe the temporary lock.
7. Use the administration panel to inspect audit events, filter logs, block users, and manage administrator privileges.
8. Request a password reset and use the one-time email link.
9. Test Google or GitHub login after configuring provider credentials.
