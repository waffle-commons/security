# Changelog — waffle-commons/security

All notable changes to this component are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Released in lockstep with the Waffle Commons umbrella tag.

## [0.1.0-beta6] — 2026-08-03

**Theme: lazy, voter-gated subject resolution.**

### Added
- `SecureContainer` accepts an optional `SubjectResolverInterface`. The subject is resolved **only after** voter discovery finds at least one `#[Voter]`, so `#[PublicAccess]` actions with no voters never invoke it — no false 403 and no hydration cost on public routes. A resolver failure is fail-closed: 403, logged on the SECURITY channel, never a silent null fallback (SEC-05).

### Changed
- `SecurityMiddleware` writes the normalised `_classname`/`_method` attributes back onto the request after unpacking the array shape, so every downstream consumer sees one canonical form.

### Fixed
- CSRF validation failures are logged on the dedicated SECURITY channel with IP and a missing-vs-invalid reason, instead of surfacing as an undifferentiated CRITICAL entry (Beta6 audit FIX-01).

### Documentation
- The README now links into the central Diátaxis documentation tree (DOC-02).

## [0.1.0-beta5] — 2026-07-08

**Theme: context-aware ABAC & voter tracing.**

### Added
- **Context-aware authorization (AUTHZ-01).** `SecureContainer::analyze()` now threads a request-scoped `SecurityContextInterface` (the authenticated identity) plus the current PSR-7 `ServerRequestInterface` into `VoterInterface::decide($context, $subject)`. Voters can finally see *who* is acting and *what* they are acting on, making ownership / IDOR rules expressible (e.g. an `OwnerVoter` that grants only when the authenticated subject matches the resource owner). Deny-by-default (no `#[Voter]` → 403 unless `#[PublicAccess]`) and the fail-closed analyze snapshot are unchanged.
- Telemetry spans on every voter consensus run: `analyze()` opens a `waffle.security.authorize` internal span (carrying `code.namespace` / `code.function`), records the exception and marks the span `Error` on denial, and always ends it — defaulting to the contracts `NullTracer` so the SDK never enters core (OBS-01).

### Changed
- **Voters are now resolved THROUGH the container (AUTHZ-01).** A `#[Voter]` class-string is fetched via the inner PSR-11 container (`$inner->get($voterName)`) instead of a context-free `new $voterName()`, so voters are autowired with their declared collaborators; an unresolvable voter fails closed as a 500 configuration error.
- `SecurityMiddleware` forwards the active request into `analyze()` so the decision subject reaches the voters.
- Enabled the Mago `cyclomatic-complexity` lint with a threshold of `50`.

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
