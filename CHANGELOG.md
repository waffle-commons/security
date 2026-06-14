# Changelog — waffle-commons/security

All notable changes to this component are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Released in lockstep with the Waffle Commons umbrella tag.

## [0.1.0-beta4] — 2026-06-13

**Theme: core security hardening (RC-readiness).**

### Added
- Session-fixation mitigation: `WAFFLE_SID` rotation on privilege change with `HttpOnly`/`Secure`/`SameSite` cookie defaults, plus cryptographic CSRF token binding to the authenticated subject / anon-sid (SEC-01).
- Fail-closed CORS: `Cors\CorsPolicy` + `Middleware\CorsMiddleware` — rejects un-allowlisted origins, bans wildcard origins on credentialed endpoints (SEC-04).

### Changed
- Timing-safe comparisons (`hash_equals()`) audited and enforced across token / CSRF surfaces (SEC-03).
- Worker-safety migration to igor-php 0.7 (`#[WorkerSafe]`).

## [0.1.0-beta3] — 2026-06-07

**Theme: identity federation & stateless persistence (ecosystem wave).**

### Added
- `SecureContainer` forwards `reset()` to the decorated container, so request-scoped services behind the security decorator join the kernel reset chain between FrankenPHP worker requests.

### Changed
- **Authentication decoupled into `waffle-commons/auth` (RFC-021).** All authentication concerns — JWT validation, OAuth2/OIDC, API keys, HTTP Basic and the `X-Wfl-Assert-User` gateway assertions — now live in the new Universal Authentication Bridge component. `security` keeps attribute-based access control (ABAC voters, `#[PublicAccess]`), the stateless HMAC CSRF manager and the secure container. **Upgrade path:** require `waffle-commons/auth`, wire `AuthenticationMiddleware` between `AnonymousSessionMiddleware` and routing, and read the verified identity from the `_auth_identity` request attribute — see `auth/CHANGELOG.md` and `documentation/how-to/authentication.md`.
- Lockstep version bump; `composer.lock` refreshed with the beta-3 dependency wave.

## [0.1.0-beta2.1] — 2026-05-30

### Changed
- Lockstep re-tag of `0.1.0-beta2` (umbrella housekeeping patch) — no source changes in this component.

## [0.1.0-beta2] — 2026-05-29

### Changed
- Lockstep version bump only. No behavioural changes since `0.1.0-beta1`.
- `composer.lock` refreshed to align with the ecosystem-wide dependency wave.

## [0.1.0-beta1]

See the umbrella [CHANGELOG](../CHANGELOG.md#010-beta1) for the full Beta-1 narrative — fail-closed ABAC default (deny without `#[Voter]` unless `#[PublicAccess]`), stateless HMAC CSRF bound to a per-browser session id via `AnonymousSessionMiddleware`, `WAFFLE_SID` cookie publication, `SecureContainer` decorator.
