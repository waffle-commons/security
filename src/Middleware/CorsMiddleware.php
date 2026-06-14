<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Waffle\Commons\Security\Cors\CorsPolicy;

/**
 * Fail-closed CORS middleware (SEC-04).
 *
 * A cross-origin request is permitted ONLY when its `Origin` exactly matches
 * the configured allow-list; with an empty allow-list every cross-origin
 * request is refused. Same-origin and Origin-less (server-to-server, curl)
 * requests pass straight through, untouched.
 *
 * - A pre-flight (`OPTIONS` + `Access-Control-Request-Method`) is answered here
 *   with `204` plus the negotiated `Access-Control-*` headers when the origin
 *   is allowed, or `403` when it is not — the application handler never runs.
 * - A disallowed cross-origin *actual* request is rejected with `403` BEFORE
 *   the handler runs (fail-closed: a forged cross-site write never executes).
 * - An allowed cross-origin response is decorated with an
 *   `Access-Control-Allow-Origin` header (the exact origin, never a blanket
 *   `*` for credentialed policies) plus `Vary: Origin`.
 *
 * Place this BEFORE routing so a pre-flight is handled ahead of the router's
 * own OPTIONS short-circuit. Stateless across requests (FrankenPHP rule).
 */
final readonly class CorsMiddleware implements MiddlewareInterface
{
    private const string PREFLIGHT_METHOD = 'OPTIONS';

    public function __construct(
        private CorsPolicy $policy,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');

        // Not a cross-origin request (no Origin, or same-origin) → untouched.
        if ($origin === '' || $origin === $this->ownOrigin($request)) {
            return $handler->handle($request);
        }

        $allowed = $this->policy->allowsOrigin($origin);

        if ($this->isPreflight($request)) {
            return $allowed ? $this->preflightResponse($origin) : $this->forbidden();
        }

        if (!$allowed) {
            return $this->forbidden();
        }

        return $this->decorate($handler->handle($request), $origin);
    }

    private function isPreflight(ServerRequestInterface $request): bool
    {
        return (
            strtoupper($request->getMethod()) === self::PREFLIGHT_METHOD
            && $request->hasHeader('Access-Control-Request-Method')
        );
    }

    private function ownOrigin(ServerRequestInterface $request): string
    {
        $uri = $request->getUri();
        $scheme = $uri->getScheme();
        $origin = $scheme . '://' . $uri->getHost();

        $port = $uri->getPort();
        if ($port !== null && !self::isDefaultPort($scheme, $port)) {
            $origin .= ':' . $port;
        }

        return $origin;
    }

    private static function isDefaultPort(string $scheme, int $port): bool
    {
        return $scheme === 'https' && $port === 443 || $scheme === 'http' && $port === 80;
    }

    private function preflightResponse(string $origin): ResponseInterface
    {
        $response = $this->responseFactory
            ->createResponse(204)
            ->withHeader('Access-Control-Allow-Origin', $origin)
            ->withHeader('Vary', 'Origin')
            ->withHeader('Access-Control-Allow-Methods', implode(', ', $this->policy->allowedMethods))
            ->withHeader('Access-Control-Allow-Headers', implode(', ', $this->policy->allowedHeaders))
            ->withHeader('Access-Control-Max-Age', (string) $this->policy->maxAge);

        return $this->policy->allowCredentials
            ? $response->withHeader('Access-Control-Allow-Credentials', 'true')
            : $response;
    }

    private function decorate(ResponseInterface $response, string $origin): ResponseInterface
    {
        $decorated = $response->withHeader('Access-Control-Allow-Origin', $origin)->withAddedHeader('Vary', 'Origin');

        return $this->policy->allowCredentials
            ? $decorated->withHeader('Access-Control-Allow-Credentials', 'true')
            : $decorated;
    }

    private function forbidden(): ResponseInterface
    {
        return $this->responseFactory->createResponse(403);
    }
}
