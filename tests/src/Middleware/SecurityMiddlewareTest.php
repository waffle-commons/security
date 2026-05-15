<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Middleware;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface as PsrContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Waffle\Commons\Contracts\Constant\Constant;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Security\Container\SecureContainer;
use Waffle\Commons\Security\Exception\SecurityException;
use Waffle\Commons\Security\Middleware\SecurityMiddleware;
use WaffleTests\Commons\Security\Helper\Controller\AllowingController;
use WaffleTests\Commons\Security\Helper\Controller\DenyingController;

#[CoversClass(SecurityMiddleware::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecurityMiddlewareTest extends TestCase
{
    private function makeContainer(): SecureContainer
    {
        return new SecureContainer(
            inner: $this->createStub(PsrContainerInterface::class),
            security: $this->createStub(SecurityInterface::class),
        );
    }

    private function makeRequest(mixed $classname = null, mixed $method = null): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request
            ->method('getAttribute')
            ->willReturnCallback(static fn(string $name) => match ($name) {
                Constant::ATTR_CLASSNAME => $classname,
                Constant::ATTR_METHOD => $method,
                default => null,
            });
        $uri = $this->createStub(UriInterface::class);
        $uri->method('__toString')->willReturn('/some-path');
        $request->method('getUri')->willReturn($uri);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '127.0.0.1']);
        return $request;
    }

    public function testPassesThroughWhenNoRouteInformation(): void
    {
        $middleware = new SecurityMiddleware(secureContainer: $this->makeContainer());
        $request = $this->makeRequest(classname: null, method: null);
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->with($request)->willReturn($response);

        static::assertSame($response, $middleware->process($request, $handler));
    }

    public function testUnpacksArrayShapedControllerAttribute(): void
    {
        $middleware = new SecurityMiddleware(secureContainer: $this->makeContainer());
        $request = $this->makeRequest(classname: [AllowingController::class, 'action'], method: null);
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        static::assertSame($response, $middleware->process($request, $handler));
    }

    public function testHandlerInvokedWhenSecurityPasses(): void
    {
        $middleware = new SecurityMiddleware(secureContainer: $this->makeContainer());
        $request = $this->makeRequest(AllowingController::class, 'action');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->with($request)->willReturn($response);

        static::assertSame($response, $middleware->process($request, $handler));
    }

    public function testDenialIsLoggedAndExceptionRethrown(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger
            ->expects($this->once())
            ->method('warning')
            ->with(
                static::stringContains('Access denied'),
                static::callback(
                    static fn(array $ctx): bool => (
                        ($ctx['ip'] ?? null) === '127.0.0.1'
                        && ($ctx['target'] ?? null) === DenyingController::class . '::action'
                    ),
                ),
            );

        $middleware = new SecurityMiddleware(secureContainer: $this->makeContainer(), logger: $logger);
        $request = $this->makeRequest(DenyingController::class, 'action');

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Security Policy Violation');

        $middleware->process($request, $handler);
    }
}
