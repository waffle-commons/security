<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionClass;
use ReflectionException;
use Waffle\Commons\Contracts\Constant\Constant;
use Waffle\Commons\Contracts\Security\Csrf\Attribute\RequiresCsrfToken;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;
use Waffle\Commons\Contracts\Security\Csrf\CsrfTokenManagerInterface;
use Waffle\Commons\Security\Csrf\Exception\InvalidCsrfTokenException;
use Waffle\Commons\Security\Csrf\Exception\MissingCsrfTokenException;

/**
 * PSR-15 middleware enforcing `#[RequiresCsrfToken]` attribute-driven CSRF checks.
 *
 * Pipeline placement (canonical Beta-1 order):
 *   ErrorHandler → TrustedHost → AnonymousSession → Routing → **Csrf** → Security → SecureHeaders → Dispatcher
 *
 * The anonymous-session middleware MUST run before this one — its
 * `_anon_sid` request attribute is the session-binding payload folded into
 * the CSRF HMAC. Without it, every validation deterministically fails-closed.
 *
 * Routing publishes `_classname`/`_method` request attributes; this middleware reads
 * them, reflects on the controller method to find a `#[RequiresCsrfToken]` attribute,
 * and rejects the request when the supplied token does not validate.
 *
 * Idempotent HTTP methods (GET, HEAD, OPTIONS, TRACE) are short-circuited and never
 * require a token — they should not mutate state, so CSRF is moot. This aligns with
 * OWASP guidance and standard browser behaviour.
 *
 * Stateless across requests (FrankenPHP worker rule): all state lives in the injected
 * `CsrfTokenManagerInterface`.
 */
final class CsrfMiddleware implements MiddlewareInterface
{
    /** HTTP methods that bypass CSRF validation. */
    private const array SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];

    public function __construct(
        private readonly CsrfTokenManagerInterface $tokenManager,
    ) {}

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (in_array(strtoupper($request->getMethod()), self::SAFE_METHODS, strict: true)) {
            return $handler->handle($request);
        }

        $required = $this->resolveRequiresAttribute($request);
        if ($required === null) {
            return $handler->handle($request);
        }

        $tokenId = $required->id;
        $candidate = $this->extractTokenValue($request);

        if ($candidate === null || $candidate === '') {
            throw new MissingCsrfTokenException(tokenId: $tokenId);
        }

        // SEC-01 option C: bind validation to the per-browser anonymous SID
        // published by AnonymousSessionMiddleware. A missing attribute means
        // the pipeline is misconfigured — treat as invalid token to fail-closed.
        $sessionId = $request->getAttribute(CsrfConstant::SESSION_REQUEST_ATTRIBUTE);
        if (!is_string($sessionId) || $sessionId === '') {
            throw new InvalidCsrfTokenException(tokenId: $tokenId);
        }

        if (!$this->tokenManager->validate($tokenId, $sessionId, $candidate)) {
            throw new InvalidCsrfTokenException(tokenId: $tokenId);
        }

        // Publish the validated id for downstream consumers (e.g. audit, controllers
        // that want to issue a refreshed token in the response). The opaque value is
        // intentionally NOT published — it MUST come from the manager only.
        $forwarded = $request->withAttribute(CsrfConstant::REQUEST_ATTRIBUTE, $tokenId);
        return $handler->handle($forwarded);
    }

    /**
     * Reads `_classname` + `_method` attributes published by routing and returns the
     * `#[RequiresCsrfToken]` attribute instance attached to that method, or null when
     * the route is not CSRF-protected.
     */
    private function resolveRequiresAttribute(ServerRequestInterface $request): ?RequiresCsrfToken
    {
        $controller = $request->getAttribute(Constant::ATTR_CLASSNAME);
        $method = $request->getAttribute(Constant::ATTR_METHOD);

        if (is_array($controller) && $method === null) {
            $method = $controller[1] ?? null;
            $controller = $controller[0] ?? null;
        }

        if (!is_string($controller) || !is_string($method) || !class_exists($controller)) {
            return null;
        }

        try {
            $reflection = new ReflectionClass($controller);
            if (!$reflection->hasMethod($method)) {
                return null;
            }
            $attributes = $reflection->getMethod($method)->getAttributes(RequiresCsrfToken::class);
        } catch (ReflectionException) {
            return null;
        }

        if ($attributes === []) {
            return null;
        }

        return $attributes[0]->newInstance();
    }

    /**
     * Token extraction precedence: header → parsed body field → cookie. The first
     * non-empty source wins. Matches the convention used by Angular/Axios
     * (`X-CSRF-Token` header) and traditional form posts (`_csrf_token` field).
     */
    private function extractTokenValue(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine(CsrfConstant::HEADER_NAME);
        if ($header !== '') {
            return $header;
        }

        $parsedBody = $request->getParsedBody();
        if (is_array($parsedBody)) {
            $field = $parsedBody[CsrfConstant::FORM_FIELD_NAME] ?? null;
            if (is_string($field) && $field !== '') {
                return $field;
            }
        }

        $cookies = $request->getCookieParams();
        $cookie = $cookies[CsrfConstant::COOKIE_NAME] ?? null;
        return is_string($cookie) && $cookie !== '' ? $cookie : null;
    }
}
