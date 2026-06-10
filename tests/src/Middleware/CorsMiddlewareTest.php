<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Waffle\Commons\Security\Cors\CorsPolicy;
use Waffle\Commons\Security\Middleware\CorsMiddleware;

#[CoversClass(CorsMiddleware::class)]
final class CorsMiddlewareTest extends TestCase
{
    private const string ALLOWED_ORIGIN = 'https://app.example.com';

    /** @var array<string, string> Headers recorded via the response double. */
    private array $headers = [];

    /** Status code the middleware requested from the response factory, if any. */
    private ?int $createdStatus = null;

    #[\Override]
    protected function setUp(): void
    {
        $this->headers = [];
        $this->createdStatus = null;
    }

    public function testOriginlessRequestPassesThroughUntouched(): void
    {
        $middleware = new CorsMiddleware(new CorsPolicy([self::ALLOWED_ORIGIN]), $this->factory());
        $request = $this->request('GET', headers: []);

        $middleware->process($request, $this->handler(expectCall: true));

        static::assertSame([], $this->headers);
        static::assertNull($this->createdStatus);
    }

    public function testSameOriginRequestPassesThroughUntouched(): void
    {
        $middleware = new CorsMiddleware(new CorsPolicy([self::ALLOWED_ORIGIN]), $this->factory());
        // Origin equals the request's own origin (https://app.example.com) → not CORS.
        $request = $this->request('POST', headers: ['Origin' => self::ALLOWED_ORIGIN]);

        $middleware->process($request, $this->handler(expectCall: true));

        static::assertSame([], $this->headers);
        static::assertNull($this->createdStatus);
    }

    public function testDisallowedCrossOriginActualRequestIsForbidden(): void
    {
        $middleware = new CorsMiddleware(new CorsPolicy([self::ALLOWED_ORIGIN]), $this->factory());
        $request = $this->request('POST', headers: ['Origin' => 'https://evil.example.com']);

        $middleware->process($request, $this->handler(expectCall: false));

        static::assertSame(403, $this->createdStatus);
    }

    public function testEmptyAllowListForbidsEveryCrossOriginRequest(): void
    {
        $middleware = new CorsMiddleware(new CorsPolicy(), $this->factory());
        // Genuinely cross-origin (Origin host ≠ request host) against an empty list.
        $request = $this->request('POST', headers: ['Origin' => 'https://app.example.com'], host: 'api.example.com');

        $middleware->process($request, $this->handler(expectCall: false));

        static::assertSame(403, $this->createdStatus);
    }

    public function testAllowedCrossOriginActualRequestIsDecorated(): void
    {
        $middleware = new CorsMiddleware(new CorsPolicy([self::ALLOWED_ORIGIN]), $this->factory());
        // Cross-origin: a different host than the request's own (app.example.com).
        $request = $this->request('POST', headers: ['Origin' => self::ALLOWED_ORIGIN], host: 'api.example.com');

        $middleware->process($request, $this->handler(expectCall: true));

        static::assertSame(self::ALLOWED_ORIGIN, $this->headers['Access-Control-Allow-Origin'] ?? null);
        static::assertSame('Origin', $this->headers['Vary'] ?? null);
        static::assertArrayNotHasKey('Access-Control-Allow-Credentials', $this->headers);
        static::assertNull($this->createdStatus);
    }

    public function testCredentialedResponseAddsCredentialsHeader(): void
    {
        $policy = new CorsPolicy([self::ALLOWED_ORIGIN], allowCredentials: true);
        $middleware = new CorsMiddleware($policy, $this->factory());
        $request = $this->request('POST', headers: ['Origin' => self::ALLOWED_ORIGIN], host: 'api.example.com');

        $middleware->process($request, $this->handler(expectCall: true));

        static::assertSame('true', $this->headers['Access-Control-Allow-Credentials'] ?? null);
        static::assertSame(self::ALLOWED_ORIGIN, $this->headers['Access-Control-Allow-Origin'] ?? null);
    }

    public function testAllowedPreflightShortCircuitsWith204AndCorsHeaders(): void
    {
        $middleware = new CorsMiddleware(new CorsPolicy([self::ALLOWED_ORIGIN]), $this->factory());
        $request = $this->request(
            'OPTIONS',
            headers: [
                'Origin' => self::ALLOWED_ORIGIN,
                'Access-Control-Request-Method' => 'POST',
            ],
            host: 'api.example.com',
        );

        $middleware->process($request, $this->handler(expectCall: false));

        static::assertSame(204, $this->createdStatus);
        static::assertSame(self::ALLOWED_ORIGIN, $this->headers['Access-Control-Allow-Origin'] ?? null);
        static::assertArrayHasKey('Access-Control-Allow-Methods', $this->headers);
        static::assertArrayHasKey('Access-Control-Allow-Headers', $this->headers);
        static::assertSame('600', $this->headers['Access-Control-Max-Age'] ?? null);
    }

    public function testDisallowedPreflightIsForbidden(): void
    {
        $middleware = new CorsMiddleware(new CorsPolicy([self::ALLOWED_ORIGIN]), $this->factory());
        $request = $this->request(
            'OPTIONS',
            headers: [
                'Origin' => 'https://evil.example.com',
                'Access-Control-Request-Method' => 'POST',
            ],
            host: 'api.example.com',
        );

        $middleware->process($request, $this->handler(expectCall: false));

        static::assertSame(403, $this->createdStatus);
    }

    public function testOptionsWithoutRequestMethodIsTreatedAsActualRequest(): void
    {
        // A bare OPTIONS (no Access-Control-Request-Method) is NOT a pre-flight;
        // when the origin is allowed it flows through and is decorated.
        $middleware = new CorsMiddleware(new CorsPolicy([self::ALLOWED_ORIGIN]), $this->factory());
        $request = $this->request('OPTIONS', headers: ['Origin' => self::ALLOWED_ORIGIN], host: 'api.example.com');

        $middleware->process($request, $this->handler(expectCall: true));

        static::assertNull($this->createdStatus);
        static::assertSame(self::ALLOWED_ORIGIN, $this->headers['Access-Control-Allow-Origin'] ?? null);
    }

    public function testNonDefaultPortIsPartOfOwnOrigin(): void
    {
        // Request to https://app.example.com:8443 with a matching Origin → same-origin.
        $middleware = new CorsMiddleware(new CorsPolicy(['https://app.example.com:8443']), $this->factory());
        $request = $this->request('POST', headers: ['Origin' => 'https://app.example.com:8443'], port: 8443);

        $middleware->process($request, $this->handler(expectCall: true));

        // Same-origin ⇒ untouched (no decoration, no rejection).
        static::assertSame([], $this->headers);
        static::assertNull($this->createdStatus);
    }

    public function testCredentialedPreflightAddsCredentialsHeader(): void
    {
        $policy = new CorsPolicy([self::ALLOWED_ORIGIN], allowCredentials: true);
        $middleware = new CorsMiddleware($policy, $this->factory());
        $request = $this->request(
            'OPTIONS',
            headers: [
                'Origin' => self::ALLOWED_ORIGIN,
                'Access-Control-Request-Method' => 'POST',
            ],
            host: 'api.example.com',
        );

        $middleware->process($request, $this->handler(expectCall: false));

        static::assertSame(204, $this->createdStatus);
        static::assertSame('true', $this->headers['Access-Control-Allow-Credentials'] ?? null);
    }

    public function testExplicitDefaultPortIsTreatedAsSameOrigin(): void
    {
        // Explicit :443 is the default for https, so the request to
        // https://app.example.com:443 is the same origin as an unported Origin.
        $middleware = new CorsMiddleware(new CorsPolicy([self::ALLOWED_ORIGIN]), $this->factory());
        $request = $this->request('POST', headers: ['Origin' => self::ALLOWED_ORIGIN], port: 443);

        $middleware->process($request, $this->handler(expectCall: true));

        static::assertSame([], $this->headers);
        static::assertNull($this->createdStatus);
    }

    /**
     * @param array<string, string> $headers
     */
    private function request(
        string $method,
        array $headers,
        string $scheme = 'https',
        string $host = 'app.example.com',
        ?int $port = null,
    ): ServerRequestInterface {
        $uri = $this->createStub(UriInterface::class);
        $uri->method('getScheme')->willReturn($scheme);
        $uri->method('getHost')->willReturn($host);
        $uri->method('getPort')->willReturn($port);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn($method);
        $request->method('getUri')->willReturn($uri);
        $request->method('getHeaderLine')->willReturnCallback(static fn(string $name): string => $headers[$name] ?? '');
        $request
            ->method('hasHeader')
            ->willReturnCallback(static fn(string $name): bool => array_key_exists($name, $headers));

        return $request;
    }

    private function factory(): ResponseFactoryInterface
    {
        $factory = $this->createStub(ResponseFactoryInterface::class);
        $factory
            ->method('createResponse')
            ->willReturnCallback(function (int $code): ResponseInterface {
                $this->createdStatus = $code;
                return $this->recordingResponse();
            });

        return $factory;
    }

    private function recordingResponse(): ResponseInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $record = function (string $name, string $value) use ($response): ResponseInterface {
            $this->headers[$name] = $value;
            return $response;
        };
        $response->method('withHeader')->willReturnCallback($record);
        $response->method('withAddedHeader')->willReturnCallback($record);

        return $response;
    }

    private function handler(bool $expectCall): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler
            ->expects($expectCall ? static::once() : static::never())
            ->method('handle')
            ->willReturn($this->recordingResponse());

        return $handler;
    }
}
