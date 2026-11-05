<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Middleware;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;
use Waffle\Commons\Contracts\Http\ClientIpResolverInterface;
use Waffle\Commons\Contracts\RateLimit\RateLimitDecision;
use Waffle\Commons\Contracts\RateLimit\RateLimiterInterface;
use Waffle\Commons\Security\Middleware\RateLimitMiddleware;
use WaffleTests\Commons\Security\Helper\Identity\FakeIdentity;

#[CoversClass(RateLimitMiddleware::class)]
final class RateLimitMiddlewareTest extends TestCase
{
    public function testAnAllowedCallReachesTheAppWithItsQuotaHeaders(): void
    {
        $limiter = $this->createMock(RateLimiterInterface::class);
        $limiter
            ->expects($this->once())
            ->method('consume')
            ->with('ip:203.0.113.7')
            ->willReturn(new RateLimitDecision(true, 100, 99, 1));

        $response = $this->middleware($limiter, null, '203.0.113.7')->process($this->request(), $this->app());

        static::assertSame(204, $response->getStatusCode());
        static::assertSame('100', $response->getHeaderLine('RateLimit-Limit'));
        static::assertSame('99', $response->getHeaderLine('RateLimit-Remaining'));
        static::assertSame('1', $response->getHeaderLine('RateLimit-Reset'));
    }

    public function testAnAuthenticatedCallIsKeyedByItsSubject(): void
    {
        $limiter = $this->createMock(RateLimiterInterface::class);
        $limiter
            ->expects($this->once())
            ->method('consume')
            ->with('sub:alice')
            ->willReturn(new RateLimitDecision(true, 100, 99, 1));

        $this->middleware($limiter, new FakeIdentity('alice'), '203.0.113.7')->process($this->request(), $this->app());
    }

    public function testACallWithoutAnAddressSharesTheAnonymousBucket(): void
    {
        $limiter = $this->createMock(RateLimiterInterface::class);
        $limiter
            ->expects($this->once())
            ->method('consume')
            ->with('anonymous')
            ->willReturn(new RateLimitDecision(true, 100, 99, 1));

        $this->middleware($limiter, null, null)->process($this->request(), $this->app());
    }

    public function testAnEmptyBucketAnswers429WithRetryAfter(): void
    {
        $limiter = $this->createStub(RateLimiterInterface::class);
        $limiter->method('consume')->willReturn(new RateLimitDecision(false, 100, 0, 60, 3));

        $response = $this->middleware($limiter, null, '203.0.113.7')->process($this->request(), $this->app());

        static::assertSame(429, $response->getStatusCode());
        static::assertSame('3', $response->getHeaderLine('Retry-After'));
        static::assertSame('0', $response->getHeaderLine('RateLimit-Remaining'));
        static::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        static::assertStringContainsString('429', (string) $response->getBody());
    }

    public function testAClosedStorageOutageAnswers503WithoutQuotaHeaders(): void
    {
        $limiter = $this->createStub(RateLimiterInterface::class);
        $limiter->method('consume')->willReturn(new RateLimitDecision(false, 100, 0, 0, 1, false));

        $response = $this->middleware($limiter, null, '203.0.113.7')->process($this->request(), $this->app());

        static::assertSame(503, $response->getStatusCode());
        static::assertSame('1', $response->getHeaderLine('Retry-After'));
        static::assertFalse($response->hasHeader('RateLimit-Limit'));
    }

    public function testAnOpenStorageOutageServesWithoutQuotaHeaders(): void
    {
        $limiter = $this->createStub(RateLimiterInterface::class);
        $limiter->method('consume')->willReturn(new RateLimitDecision(true, 100, 100, 0, 0, false));

        $response = $this->middleware($limiter, null, '203.0.113.7')->process($this->request(), $this->app());

        static::assertSame(204, $response->getStatusCode());
        static::assertFalse($response->hasHeader('RateLimit-Limit'));
    }

    private function middleware(
        RateLimiterInterface $limiter,
        ?UserIdentityInterface $identity,
        ?string $ip,
    ): RateLimitMiddleware {
        $context = $this->createStub(SecurityContextInterface::class);
        $context->method('getIdentity')->willReturn($identity);
        $resolver = $this->createStub(ClientIpResolverInterface::class);
        $resolver->method('resolve')->willReturn($ip);

        return new RateLimitMiddleware($limiter, $resolver, $context, new Psr17Factory());
    }

    private function request(): ServerRequestInterface
    {
        return new Psr17Factory()->createServerRequest('GET', '/api/orders');
    }

    private function app(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            #[\Override]
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Psr17Factory()->createResponse(204);
            }
        };
    }
}
