[![PHP Version Require](http://poser.pugx.org/waffle-commons/security/require/php)](https://packagist.org/packages/waffle-commons/security)
[![PHP CI](https://github.com/waffle-commons/security/actions/workflows/main.yml/badge.svg)](https://github.com/waffle-commons/security/actions/workflows/main.yml)
[![codecov](https://codecov.io/gh/waffle-commons/security/graph/badge.svg?token=d74ac62a-7872-4035-8b8b-bcc3af1991e0)](https://codecov.io/gh/waffle-commons/security)
[![Latest Stable Version](http://poser.pugx.org/waffle-commons/security/v)](https://packagist.org/packages/waffle-commons/security)
[![Latest Unstable Version](http://poser.pugx.org/waffle-commons/security/v/unstable)](https://packagist.org/packages/waffle-commons/security)
[![Total Downloads](https://img.shields.io/packagist/dt/waffle-commons/security.svg)](https://packagist.org/packages/waffle-commons/security)
[![Packagist License](https://img.shields.io/packagist/l/waffle-commons/security)](https://github.com/waffle-commons/security/blob/main/LICENSE.md)

Waffle Security Component
=========================

> **Release:** `v0.1.0-beta0`

Hierarchical Attribute-Based Access Control (ABAC) for the Waffle Framework, plus a stateless CSRF protection layer and a container decorator (`SecureContainer`) that hardens service retrieval. Security is enforced by PSR-15 middleware sitting after routing in the pipeline.

## 📦 Installation

```bash
composer require waffle-commons/security
```

## 🧱 Surface

| Class | Role |
| :--- | :--- |
| `Waffle\Commons\Security\Security` | `SecurityInterface` implementation. Reads `waffle.security.level` from `ConfigInterface` at construction (defaults to `1`). |
| `Waffle\Commons\Security\Abstract\AbstractSecurity` | Shared base storing the configured security level and providing the `analyze()` walk. |
| `Waffle\Commons\Security\Middleware\SecurityMiddleware` | PSR-15 middleware that runs `Security::analyze()` against the resolved controller. |
| `Waffle\Commons\Security\Middleware\CsrfMiddleware` | Stateless CSRF middleware (double-submit cookie + signed token). |
| `Waffle\Commons\Security\Container\SecureContainer` | Decorator over `Waffle\Commons\Contracts\Container\ContainerInterface` enforcing the security level on `get()` calls. |
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

## 🛂 CSRF middleware (stateless)

`CsrfMiddleware` implements double-submit-cookie CSRF protection with HMAC-signed tokens. No PHP sessions are touched — the implementation is FrankenPHP-safe. Tokens are issued and validated via `CsrfTokenManagerInterface` (from the contracts package). Controllers opt in with `#[RequiresCsrfToken]`.

## 🛡️ `SecureContainer`

A `Waffle\Commons\Security\Container\SecureContainer` decorator wraps any `ContainerInterface` and runs the security check before `get($id)` returns the service — preventing low-privilege code paths from pulling sensitive services out of the container.

## 🐘 PHP 8.5 features used

- Typed constructors throughout (`Security` takes `ConfigInterface`, level resolution is `?int ?? 1`).
- Typed integer security levels declared as typed constants in `Constant::SECURITY_LEVEL*`.
- `#[Rule]` / `#[Voter]` / `#[RequiresCsrfToken]` attributes from the contracts package.
- `final readonly class CsrfToken` value object.

## 🧪 Testing

```bash
docker exec -w /waffle-commons/security waffle-dev composer tests
```

## 📄 License

MIT — see [LICENSE.md](./LICENSE.md).
