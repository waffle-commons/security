<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use ReflectionClass;
use ReflectionException;
use Waffle\Commons\Contracts\Constant\Constant;
use Waffle\Commons\Contracts\Security\Csrf\Attribute\RequiresCsrfToken;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;
use Waffle\Commons\Contracts\Security\Csrf\CsrfTokenManagerInterface;
use Waffle\Commons\Security\Csrf\CsrfBindingResolver;
use Waffle\Commons\Security\Csrf\Exception\CsrfException;
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
        private readonly ?LoggerInterface $logger = null,
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
            $exception = new MissingCsrfTokenException(tokenId: $tokenId);
            $this->logDenial($request, $exception, 'missing');
            throw $exception;
        }

        // SEC-01: bind validation to the authenticated subject when present,
        // else the per-browser anonymous SID (see CsrfBindingResolver). A token
        // minted while anonymous therefore cannot validate once the session
        // authenticates (session tossing). A null binding means the pipeline is
        // misconfigured (no SID published) — treat as invalid to fail-closed.
        $binding = CsrfBindingResolver::resolve($request);
        if ($binding === null) {
            $exception = new InvalidCsrfTokenException(tokenId: $tokenId);
            $this->logDenial($request, $exception, 'invalid (no binding published)');
            throw $exception;
        }

        if (!$this->tokenManager->validate($tokenId, $binding, $candidate)) {
            $exception = new InvalidCsrfTokenException(tokenId: $tokenId);
            $this->logDenial($request, $exception, 'invalid (attempted forgery or stale token)');
            throw $exception;
        }

        // Publish the validated id for downstream consumers (e.g. audit, controllers
        // that want to issue a refreshed token in the response). The opaque value is
        // intentionally NOT published — it MUST come from the manager only.
        $forwarded = $request->withAttribute(CsrfConstant::REQUEST_ATTRIBUTE, $tokenId);
        return $handler->handle($forwarded);
    }

    /**
     * Logs a CSRF denial on the SECURITY channel — mirrors SecurityMiddleware's
     * own audit path, which this middleware otherwise bypasses entirely (its
     * exception type deliberately doesn't extend SecurityException). $reason
     * differentiates "dropped the token" from "attempted to forge one" per
     * {@see \Waffle\Commons\Contracts\Security\Csrf\Exception\MissingCsrfTokenExceptionInterface}'s
     * own documented intent.
     */
    private function logDenial(ServerRequestInterface $request, CsrfException $e, string $reason): void
    {
        $this->logger?->warning('[csrf] Token rejected: ' . $e->getMessage(), [
            'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown',
            'uri' => (string) $request->getUri(),
            'reason' => $reason,
        ]);
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
