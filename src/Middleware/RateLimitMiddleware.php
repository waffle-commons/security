<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Http\ClientIpResolverInterface;
use Waffle\Commons\Contracts\RateLimit\RateLimitDecision;
use Waffle\Commons\Contracts\RateLimit\RateLimiterInterface;

/**
 * Token-bucket rate limiting at the edge ([NET-01], RFC-017 §3.1). Stateless.
 *
 * The key is the authenticated subject when there is one (mount it after authentication), the client IP
 * resolved behind trusted proxies otherwise. An empty bucket answers `429` with `Retry-After`; a storage
 * outage under `on_storage_failure: closed` answers `503`. Enforced decisions carry `RateLimit-Limit`,
 * `RateLimit-Remaining` and `RateLimit-Reset` on every response.
 */
final readonly class RateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(
        private RateLimiterInterface $limiter,
        private ClientIpResolverInterface $clientIp,
        private SecurityContextInterface $securityContext,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    /** @throws \InvalidArgumentException From the PSR-17 factory on an invalid status code. */
    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $decision = $this->limiter->consume($this->key($request));

        if ($decision->allowed) {
            return self::withQuota($handler->handle($request), $decision);
        }

        $status = $decision->enforced ? 429 : 503;
        $response = $this->responseFactory
            ->createResponse($status)
            ->withHeader('Content-Type', 'application/problem+json')
            ->withHeader('Retry-After', (string) $decision->retryAfterSeconds);
        $response
            ->getBody()
            ->write(
                $decision->enforced
                    ? '{"title":"Too Many Requests","status":429}'
                    : '{"title":"Service Unavailable","status":503}',
            );

        return self::withQuota($response, $decision);
    }

    private function key(ServerRequestInterface $request): string
    {
        $identity = $this->securityContext->getIdentity();
        if ($identity !== null) {
            return 'sub:' . $identity->subject;
        }

        $ip = $this->clientIp->resolve($request);

        return $ip === null ? 'anonymous' : 'ip:' . $ip;
    }

    private static function withQuota(ResponseInterface $response, RateLimitDecision $decision): ResponseInterface
    {
        if (!$decision->enforced) {
            return $response;
        }

        return $response
            ->withHeader('RateLimit-Limit', (string) $decision->limit)
            ->withHeader('RateLimit-Remaining', (string) $decision->remaining)
            ->withHeader('RateLimit-Reset', (string) $decision->resetSeconds);
    }
}
