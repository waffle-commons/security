<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;

/**
 * Mints / propagates a per-browser anonymous session identifier (Beta-1 /
 * SEC-01 option C) and rotates it on authentication (SEC-01 session fixation).
 *
 * The framework does not (and must not, under the FrankenPHP rule) touch
 * `$_SESSION`. CSRF protection, however, needs *something* to bind a token to
 * a specific browser, otherwise an attacker who steals a token from one
 * browser can replay it from another. This middleware provides that
 * "something": a long, random, opaque cookie value (`WAFFLE_SID`) whose only
 * job is to be a stable per-browser handle the CSRF HMAC payload can include.
 *
 * Pipeline placement (canonical Beta-1 order):
 *   ErrorHandler → TrustedHost → **AnonymousSession** → Authentication →
 *   Routing → Csrf → Security → SecureHeaders → Dispatcher
 *
 * It MUST run before {@see CsrfMiddleware}, because the CSRF middleware reads
 * the published request attribute. It sits ABOVE the AuthenticationMiddleware,
 * so on the response path the injected {@see SecurityContextInterface} already
 * reflects whether the request authenticated — enabling SID rotation.
 *
 * Behaviour:
 *   - If the request carries a `WAFFLE_SID` cookie of the expected shape, the
 *     middleware reuses it and just publishes it as a request attribute.
 *   - Otherwise it generates a fresh 32-byte random id, base64url-encodes it,
 *     publishes it as a request attribute, and adds a `Set-Cookie` header to
 *     the outbound response so the same browser carries it on the next call.
 *   - **SEC-01 (session fixation):** when a pre-existing SID was presented AND
 *     the request authenticated, the id is *rotated* (a fresh value is issued)
 *     so a value an attacker fixed before login cannot ride the now-privileged
 *     session.
 *
 * The `Secure` cookie flag is emitted on HTTPS requests, or unconditionally
 * when `$forceSecureCookie` is set (for deployments behind a TLS-terminating
 * proxy that forwards plain HTTP).
 *
 * Stateless across requests (FrankenPHP rule): the middleware itself holds no
 * cross-request state — the cookie carries it.
 */
final readonly class AnonymousSessionMiddleware implements MiddlewareInterface
{
    /** Base64url-encoded length of a 32-byte payload (no padding). */
    private const int ENCODED_LENGTH = 43;

    /** Strict shape check for an inbound cookie value. */
    private const string SHAPE_REGEX = '/^[A-Za-z0-9_\-]{43}$/';

    public function __construct(
        private ?SecurityContextInterface $securityContext = null,
        private bool $forceSecureCookie = false,
    ) {}

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        [$sessionId, $issued] = $this->resolveSessionId($request);

        $enriched = $request->withAttribute(CsrfConstant::SESSION_REQUEST_ATTRIBUTE, $sessionId);
        $response = $handler->handle($enriched);

        $secure = $this->forceSecureCookie || $this->isSecureScheme($request);

        if ($issued) {
            // First contact (or a malformed cookie): persist the minted id.
            return $response->withAddedHeader('Set-Cookie', $this->buildSetCookie($sessionId, $secure));
        }

        if ($this->securityContext?->isAuthenticated() === true) {
            // SEC-01 session-fixation: a pre-existing SID was presented AND the
            // request authenticated — rotate it so a value an attacker fixed
            // before login can never ride the now-privileged session.
            return $response->withAddedHeader('Set-Cookie', $this->buildSetCookie(self::generate(), $secure));
        }

        return $response;
    }

    /**
     * @return array{0: string, 1: bool} [sessionId, wasNewlyIssued]
     */
    private function resolveSessionId(ServerRequestInterface $request): array
    {
        $cookies = $request->getCookieParams();
        $existing = $cookies[CsrfConstant::SESSION_COOKIE_NAME] ?? null;

        if (is_string($existing) && preg_match(self::SHAPE_REGEX, $existing) === 1) {
            return [$existing, false];
        }

        return [self::generate(), true];
    }

    private static function generate(): string
    {
        $raw = random_bytes(CsrfConstant::SESSION_ID_BYTES);
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private function buildSetCookie(string $sessionId, bool $secure): string
    {
        $parts = [
            CsrfConstant::SESSION_COOKIE_NAME . '=' . $sessionId,
            'Path=/',
            'Max-Age=' . CsrfConstant::SESSION_COOKIE_MAX_AGE,
            'HttpOnly',
            'SameSite=Lax',
        ];

        if ($secure) {
            $parts[] = 'Secure';
        }

        return implode('; ', $parts);
    }

    private function isSecureScheme(ServerRequestInterface $request): bool
    {
        return strtolower($request->getUri()->getScheme()) === 'https';
    }
}
