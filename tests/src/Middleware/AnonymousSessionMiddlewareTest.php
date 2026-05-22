<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;
use Waffle\Commons\Security\Middleware\AnonymousSessionMiddleware;

#[CoversClass(AnonymousSessionMiddleware::class)]
final class AnonymousSessionMiddlewareTest extends TestCase
{
    public function testMintsAndPublishesSessionIdWhenCookieAbsent(): void
    {
        $middleware = new AnonymousSessionMiddleware();
        $request = $this->buildRequest(cookies: [], scheme: 'https');
        $request
            ->expects(static::once())
            ->method('withAttribute')
            ->with(CsrfConstant::SESSION_REQUEST_ATTRIBUTE, $this->callback(static function (mixed $value): bool {
                return is_string($value) && preg_match('/^[A-Za-z0-9_\-]{43}$/', $value) === 1;
            }))
            ->willReturnSelf();

        $response = $this->expectResponseWithAddedCookie(static function (string $cookie): bool {
            return (
                str_starts_with($cookie, CsrfConstant::SESSION_COOKIE_NAME . '=')
                && str_contains($cookie, 'Path=/')
                && str_contains($cookie, 'HttpOnly')
                && str_contains($cookie, 'SameSite=Lax')
                && str_contains($cookie, 'Secure')
            );
        });

        $handler = $this->handlerReturning($response['original']);

        static::assertSame($response['decorated'], $middleware->process($request, $handler));
    }

    public function testReusesExistingValidCookieAndDoesNotEmitSetCookie(): void
    {
        // Exactly 43 base64url characters (= base64url(32 bytes), no padding) —
        // matches AnonymousSessionMiddleware's shape regex.
        $existing = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $middleware = new AnonymousSessionMiddleware();
        $request = $this->buildRequest(cookies: [CsrfConstant::SESSION_COOKIE_NAME => $existing], scheme: 'https');
        $request
            ->expects(static::once())
            ->method('withAttribute')
            ->with(CsrfConstant::SESSION_REQUEST_ATTRIBUTE, $existing)
            ->willReturnSelf();

        // No Set-Cookie expected — return a plain response straight through.
        $response = $this->createMock(ResponseInterface::class);
        $response->expects(static::never())->method('withAddedHeader');

        $handler = $this->handlerReturning($response);

        static::assertSame($response, $middleware->process($request, $handler));
    }

    public function testMintsFreshSessionIdWhenCookieMalformed(): void
    {
        // Wrong length, wrong charset → must be treated as absent.
        $middleware = new AnonymousSessionMiddleware();
        $request = $this->buildRequest(cookies: [
            CsrfConstant::SESSION_COOKIE_NAME => 'not!base64url!!!',
        ], scheme: 'https');
        $request
            ->expects(static::once())
            ->method('withAttribute')
            ->with(CsrfConstant::SESSION_REQUEST_ATTRIBUTE, $this->callback(static function (mixed $value): bool {
                return (
                    is_string($value)
                    && $value !== 'not!base64url!!!'
                    && preg_match('/^[A-Za-z0-9_\-]{43}$/', $value) === 1
                );
            }))
            ->willReturnSelf();

        $response = $this->expectResponseWithAddedCookie(static fn(): bool => true);
        $handler = $this->handlerReturning($response['original']);

        static::assertSame($response['decorated'], $middleware->process($request, $handler));
    }

    public function testOmitsSecureFlagOnPlainHttp(): void
    {
        $middleware = new AnonymousSessionMiddleware();
        $request = $this->buildRequest(cookies: [], scheme: 'http');
        $request->method('withAttribute')->willReturnSelf();

        $response = $this->expectResponseWithAddedCookie(static function (string $cookie): bool {
            return !str_contains($cookie, 'Secure');
        });

        $handler = $this->handlerReturning($response['original']);
        $middleware->process($request, $handler);
    }

    /**
     * @param array<string, string> $cookies
     */
    private function buildRequest(array $cookies, string $scheme): ServerRequestInterface
    {
        $uri = $this->createStub(UriInterface::class);
        $uri->method('getScheme')->willReturn($scheme);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getCookieParams')->willReturn($cookies);
        $request->method('getUri')->willReturn($uri);
        return $request;
    }

    /**
     * @param callable(string): bool $matcher Cookie-string predicate.
     * @return array{original: ResponseInterface, decorated: ResponseInterface}
     */
    private function expectResponseWithAddedCookie(callable $matcher): array
    {
        $decorated = $this->createStub(ResponseInterface::class);
        $original = $this->createMock(ResponseInterface::class);
        $original
            ->expects(static::once())
            ->method('withAddedHeader')
            ->with('Set-Cookie', $this->callback($matcher))
            ->willReturn($decorated);

        return ['original' => $original, 'decorated' => $decorated];
    }

    private function handlerReturning(ResponseInterface $response): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(static::once())->method('handle')->willReturn($response);
        return $handler;
    }
}
