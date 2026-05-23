[![PHP Version Require](http://poser.pugx.org/waffle-commons/security/require/php)](https://packagist.org/packages/waffle-commons/security)
[![PHP CI](https://github.com/waffle-commons/security/actions/workflows/main.yml/badge.svg)](https://github.com/waffle-commons/security/actions/workflows/main.yml)
[![codecov](https://codecov.io/gh/waffle-commons/security/graph/badge.svg?token=d74ac62a-7872-4035-8b8b-bcc3af1991e0)](https://codecov.io/gh/waffle-commons/security)
[![Latest Stable Version](http://poser.pugx.org/waffle-commons/security/v)](https://packagist.org/packages/waffle-commons/security)
[![Latest Unstable Version](http://poser.pugx.org/waffle-commons/security/v/unstable)](https://packagist.org/packages/waffle-commons/security)
[![Total Downloads](https://img.shields.io/packagist/dt/waffle-commons/security.svg)](https://packagist.org/packages/waffle-commons/security)
[![Packagist License](https://img.shields.io/packagist/l/waffle-commons/security)](https://github.com/waffle-commons/security/blob/main/LICENSE.md)

Waffle Security Component
=========================

> **Release:** `v0.1.0-beta1`

Hierarchical Attribute-Based Access Control (ABAC) for the Waffle Framework with a **fail-closed default** (Beta-1 / SEC-02), a fully **stateless HMAC CSRF subsystem** bound to a per-browser anonymous SID (Beta-1 / SEC-01 option C), and a container decorator (`SecureContainer`) that hardens service retrieval. Security is enforced by PSR-15 middleware sitting between routing and dispatch.

## 🆕 Beta-1 highlights

- **Fail-closed ABAC** — `SecureContainer::analyze()` rejects any action without a `#[Voter]` unless explicitly tagged `#[PublicAccess]`. Missing policy is now denial, not silent allow.
- **Stateless HMAC CSRF** — `CsrfTokenManager` issues self-validating signed tokens; **no cache, no Redis, no PHP sessions**. The HMAC binds to `(id, sessionId)` so a token cannot be replayed across forms or across browsers.
- **`AnonymousSessionMiddleware`** — issues the `WAFFLE_SID` cookie that anchors CSRF binding. Stateless across requests (FrankenPHP-safe).

## 📦 Installation

```bash
composer require waffle-commons/security
```

## 🧱 Surface

| Class | Role |
| :--- | :--- |
| `Waffle\Commons\Security\Security` | `SecurityInterface` implementation. Reads `waffle.security.level` from `ConfigInterface` at construction (defaults to `1`). |
| `Waffle\Commons\Security\Abstract\AbstractSecurity` | Shared base storing the configured security level and providing the `analyze()` walk. |
| `Waffle\Commons\Security\Middleware\SecurityMiddleware` | PSR-15 middleware that runs `SecureContainer::analyze($controller, $method)` — fail-closed ABAC. |
| `Waffle\Commons\Security\Middleware\AnonymousSessionMiddleware` | PSR-15 middleware that issues / reuses the `WAFFLE_SID` cookie and publishes the SID as the `_anon_sid` request attribute. **Required upstream of `CsrfMiddleware`.** |
| `Waffle\Commons\Security\Middleware\CsrfMiddleware` | PSR-15 middleware enforcing `#[RequiresCsrfToken]`. Validates the signed token against `(id, sessionId)`. |
| `Waffle\Commons\Security\Csrf\CsrfTokenManager` | `final readonly` stateless HMAC-SHA256 token manager. Constructor takes a 32+ byte secret. |
| `Waffle\Commons\Security\Container\SecureContainer` | Decorator over `Waffle\Commons\Contracts\Container\ContainerInterface`. **Beta-1:** `analyze()` is now fail-closed — empty voter list ⇒ `SecurityException(403)` unless `#[PublicAccess]` is present. |
| `Waffle\Commons\Security\Rule\Level1Rule` … `Level10Rule` | The ten built-in security levels (1 = public … 10 = god-mode). |

## 🚦 The security ladder

Each `LevelNRule` lives in `src/Rule/`. Levels are integer-coded via `Waffle\Commons\Contracts\Constant\Constant::SECURITY_LEVEL1 … SECURITY_LEVEL10`. The kernel reads `waffle.security.level` from the application's `app.yaml` and constructs `Security` with that level.

```yaml
# config/app.yaml
waffle:
  security:
    level: 5  # Authenticated user with elevated permissions
```

```php
use Waffle\Commons\Security\Security;
use Waffle\Commons\Contracts\Config\ConfigInterface;

$security = new Security($config); // reads waffle.security.level
$security->analyze($controller);   // throws SecurityExceptionInterface if rules fail
```

The exact constructor, verbatim from `src/Security.php`:

```php
final class Security extends AbstractSecurity
{
    public function __construct(ConfigInterface $cfg)
    {
        $this->level = $cfg->getInt(key: 'waffle.security.level', default: 1) ?? 1;
    }
}
```

## 🏷️ `#[Rule]` — declaring required levels

The attribute lives in the contracts package (`Waffle\Commons\Contracts\Security\Attribute\Rule`). Apply it to controller methods or classes:

```php
use Waffle\Commons\Contracts\Security\Attribute\Rule;
use Waffle\Commons\Contracts\Constant\Constant;

final class AdminController
{
    #[Rule(level: Constant::SECURITY_LEVEL10)]
    public function dangerous(): Response { /* … */ }
}
```

If `Security::analyze()` is invoked against a controller method that requires a level higher than the kernel's configured level, a `SecurityExceptionInterface` is thrown and the `ErrorHandlerMiddleware` renders it as RFC 7807 `403`.

## 🚪 Fail-closed ABAC + `#[PublicAccess]` (Beta-1 / SEC-02)

A controller action without any `#[Voter]` is now **denied with HTTP `403`** unless it explicitly carries `#[PublicAccess]`. Forgetting to attach a voter no longer silently grants access — missing policy is treated as denial.

```php
use Waffle\Commons\Contracts\Security\Attribute\PublicAccess;
use Waffle\Commons\Routing\Attribute\Route;

final class HealthController
{
    #[Route(path: '/health', name: 'health')]
    #[PublicAccess]
    public function ping(): Response { /* … */ }
}
```

A method-level `#[Voter]` always wins over a class-level `#[PublicAccess]`, so mixed-policy controllers stay safe.

## 🛂 CSRF — stateless signed double-submit with per-browser binding (Beta-1 / SEC-01)

`CsrfMiddleware` enforces `#[RequiresCsrfToken]` using HMAC-signed self-validating tokens. **No cache, no Redis, no PHP sessions.** Wire format (binary, then base64url):

```
nonce (16 bytes) || expiresAt (8 bytes BE uint64) || HMAC-SHA256(nonce || expiresAt || id || sessionId, secret)
```

Two pieces of context are folded into the HMAC:

- the **logical id** (e.g. `form:login`) — prevents cross-form replay;
- the **anonymous session id** (the `WAFFLE_SID` cookie value, published as the `_anon_sid` request attribute by `AnonymousSessionMiddleware`) — prevents cross-browser replay.

Operational requirements:

1. Provide a 32+ byte signing secret. Production refuses to boot without one. Config key `waffle.security.csrf.secret`, with env fallback `WAFFLE_CSRF_SECRET`.
2. Wire `AnonymousSessionMiddleware` **before** `CsrfMiddleware` in the pipeline. The skeleton's `AppKernelFactory` does this for you.

```yaml
# config/app.yaml
waffle:
  security:
    level: 5
    csrf:
      secret: '%env(WAFFLE_CSRF_SECRET)%'
```

```php
$csrfTokenManager = new CsrfTokenManager(secret: $csrfSecret);
$container->set(CsrfTokenManagerInterface::class, $csrfTokenManager);

$stack
    ->add(new AnonymousSessionMiddleware())
    ->add(new CoreRoutingMiddleware($router))
    ->add(new CsrfMiddleware($csrfTokenManager))
    ->add(new SecurityMiddleware($secureContainer, $logger));
```

## 🛡️ `SecureContainer`

`Waffle\Commons\Security\Container\SecureContainer` wraps any `ContainerInterface` and runs the security check before `get($id)` returns the service — preventing low-privilege code paths from pulling sensitive services out of the container.

`analyze($controller, $method)` is **fail-closed** as of Beta-1: an empty `#[Voter]` list throws `SecurityException(403)` unless the target carries `#[PublicAccess]`. Otherwise every voter must approve (consensus pattern) for the call to proceed.

## 🐘 PHP 8.5 features used

- Typed constructors throughout (`Security` takes `ConfigInterface`, level resolution is `?int ?? 1`).
- Typed integer security levels declared as typed constants in `Constant::SECURITY_LEVEL*`.
- `#[Rule]` / `#[Voter]` / `#[RequiresCsrfToken]` / `#[PublicAccess]` attributes from the contracts package.
- `final readonly class CsrfToken` value object; `final readonly class CsrfTokenManager` (no instance state across requests).
- `#[\SensitiveParameter]` on the CSRF signing secret to suppress its value from stack traces and error reports.

## 🧪 Testing

```bash
docker exec -w /waffle-commons/security waffle-dev composer tests
```

## 📄 License

MIT — see [LICENSE.md](./LICENSE.md).
