<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Csrf;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Contracts\Auth\Constant as AuthConstant;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;

/**
 * Derives the principal a CSRF token is cryptographically bound to (SEC-01).
 *
 * Binding precedence, highest first:
 *   1. `auth:<subject>` — the authenticated identity's stable subject, when the
 *      AuthenticationMiddleware has published a {@see UserIdentityInterface} on
 *      the `_auth_identity` request attribute;
 *   2. `anon:<sid>` — the per-browser anonymous session id minted by
 *      {@see \Waffle\Commons\Security\Middleware\AnonymousSessionMiddleware}.
 *
 * Folding the authenticated subject into the HMAC payload means a token minted
 * while anonymous (`anon:…`) is mathematically invalid the instant the session
 * authenticates (`auth:…`) — defeating **session tossing**, where an attacker
 * pre-seeds a CSRF token under an anonymous session and replays it post-login.
 * The disjoint `auth:` / `anon:` namespaces also prevent any value collision
 * between a subject and a session id.
 *
 * Pure and stateless: it derives solely from request attributes.
 */
final class CsrfBindingResolver
{
    /**
     * Sealed: a static-only helper that must never be instantiated.
     *
     * @codeCoverageIgnore
     */
    private function __construct() {}

    /**
     * Returns the binding principal, or null when neither an authenticated
     * identity nor an anonymous session id is available — the caller MUST then
     * fail closed (treat the token as invalid).
     */
    public static function resolve(ServerRequestInterface $request): ?string
    {
        $identity = $request->getAttribute(AuthConstant::REQUEST_ATTRIBUTE);
        if ($identity instanceof UserIdentityInterface && $identity->subject !== '') {
            return 'auth:' . $identity->subject;
        }

        $sessionId = $request->getAttribute(CsrfConstant::SESSION_REQUEST_ATTRIBUTE);
        if (is_string($sessionId) && $sessionId !== '') {
            return 'anon:' . $sessionId;
        }

        return null;
    }
}
