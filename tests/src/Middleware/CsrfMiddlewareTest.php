<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Waffle\Commons\Contracts\Constant\Constant;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;
use Waffle\Commons\Contracts\Security\Csrf\CsrfTokenManagerInterface;
use Waffle\Commons\Security\Csrf\Exception\InvalidCsrfTokenException;
use Waffle\Commons\Security\Csrf\Exception\MissingCsrfTokenException;
use Waffle\Commons\Security\Middleware\CsrfMiddleware;
use WaffleTests\Commons\Security\Helper\Controller\CsrfController;

#[CoversClass(CsrfMiddleware::class)]
final class CsrfMiddlewareTest extends TestCase
{
    /** Stable SID stand-in for stubbed requests (matches the AnonymousSession contract). */
    private const string TEST_SID = 'sid-abcdef0123456789abcdef0123456789abcdef0123';

    public function testGetRequestBypassesCsrfChecksEntirely(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::never())->method('validate');

        $middleware = new CsrfMiddleware($manager);
        $request = $this->buildRequest(method: 'GET', controller: CsrfController::class, action: 'protected');
        $handler = $this->expectingHandler();

        $middleware->process($request, $handler);
    }

    public function testHeadOptionsAndTraceAlsoBypass(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::never())->method('validate');
        $middleware = new CsrfMiddleware($manager);
        $handler = $this->expectingHandler(callCount: 3);

        foreach (['HEAD', 'OPTIONS', 'TRACE'] as $method) {
            $request = $this->buildRequest(method: $method, controller: CsrfController::class, action: 'protected');
            $middleware->process($request, $handler);
        }
    }

    public function testPostWithoutRequiresAttributePassesThrough(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::never())->method('validate');
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(method: 'POST', controller: CsrfController::class, action: 'unprotected');
        $middleware->process($request, $this->expectingHandler());
    }

    public function testMissingTokenThrowsMissingException(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::never())->method('validate');
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(method: 'POST', controller: CsrfController::class, action: 'protected');

        $this->expectException(MissingCsrfTokenException::class);
        $middleware->process($request, $this->neverCalledHandler());
    }

    public function testMissingSessionIdAttributeFailsClosed(): void
    {
        // SEC-01 option C: without the AnonymousSessionMiddleware-published SID,
        // CsrfMiddleware MUST refuse validation. Treated as invalid token.
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::never())->method('validate');
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(
            method: 'POST',
            controller: CsrfController::class,
            action: 'protected',
            headers: [CsrfConstant::HEADER_NAME => 'irrelevant'],
            sessionId: null,
        );

        $this->expectException(InvalidCsrfTokenException::class);
        $middleware->process($request, $this->neverCalledHandler());
    }

    public function testInvalidTokenThrowsInvalidException(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager
            ->expects(static::once())
            ->method('validate')
            ->with('form:test', self::TEST_SID, 'forged')
            ->willReturn(false);
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(
            method: 'POST',
            controller: CsrfController::class,
            action: 'protected',
            headers: [CsrfConstant::HEADER_NAME => 'forged'],
        );

        $this->expectException(InvalidCsrfTokenException::class);
        $middleware->process($request, $this->neverCalledHandler());
    }

    public function testValidHeaderTokenIsAccepted(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager
            ->expects(static::once())
            ->method('validate')
            ->with('form:test', self::TEST_SID, 'ok')
            ->willReturn(true);
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(
            method: 'POST',
            controller: CsrfController::class,
            action: 'protected',
            headers: [CsrfConstant::HEADER_NAME => 'ok'],
        );

        $middleware->process($request, $this->expectingHandler());
    }

    public function testValidFormFieldTokenIsAccepted(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::once())->method('validate')->willReturn(true);
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(
            method: 'POST',
            controller: CsrfController::class,
            action: 'protected',
            parsedBody: [CsrfConstant::FORM_FIELD_NAME => 'token-from-form'],
        );

        $middleware->process($request, $this->expectingHandler());
    }

    public function testValidCookieTokenIsAccepted(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::once())->method('validate')->willReturn(true);
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(
            method: 'POST',
            controller: CsrfController::class,
            action: 'protected',
            cookies: [CsrfConstant::COOKIE_NAME => 'token-from-cookie'],
        );

        $middleware->process($request, $this->expectingHandler());
    }

    public function testHeaderTakesPrecedenceOverCookieAndForm(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager
            ->expects(static::once())
            ->method('validate')
            ->with('form:test', self::TEST_SID, 'from-header')
            ->willReturn(true);
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(
            method: 'POST',
            controller: CsrfController::class,
            action: 'protected',
            headers: [CsrfConstant::HEADER_NAME => 'from-header'],
            parsedBody: [CsrfConstant::FORM_FIELD_NAME => 'from-form'],
            cookies: [CsrfConstant::COOKIE_NAME => 'from-cookie'],
        );

        $middleware->process($request, $this->expectingHandler());
    }

    public function testUnknownControllerClassPassesThrough(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::never())->method('validate');
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(method: 'POST', controller: '\\Not\\A\\Real\\Class', action: 'protected');

        $middleware->process($request, $this->expectingHandler());
    }

    public function testMissingMethodPassesThrough(): void
    {
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::never())->method('validate');
        $middleware = new CsrfMiddleware($manager);

        $request = $this->buildRequest(method: 'POST', controller: CsrfController::class, action: 'nonexistent');

        $middleware->process($request, $this->expectingHandler());
    }

    public function testControllerArrayAttributeShape(): void
    {
        // Routing may publish controller+method as a packed [Class, Method] array.
        $manager = $this->createMock(CsrfTokenManagerInterface::class);
        $manager->expects(static::once())->method('validate')->willReturn(true);
        $middleware = new CsrfMiddleware($manager);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request
            ->method('getAttribute')
            ->willReturnCallback(static function ($name) {
                return match ($name) {
                    Constant::ATTR_CLASSNAME => [CsrfController::class, 'protected'],
                    Constant::ATTR_METHOD => null,
                    CsrfConstant::SESSION_REQUEST_ATTRIBUTE => self::TEST_SID,
                    default => null,
                };
            });
        $request->method('getHeaderLine')->willReturn('header-token');
        $request->method('getParsedBody')->willReturn(null);
        $request->method('getCookieParams')->willReturn([]);
        $request->method('withAttribute')->willReturnSelf();

        $middleware->process($request, $this->expectingHandler());
    }

    /**
     * @param array<string, string>      $headers
     * @param array<string, mixed>|null  $parsedBody
     * @param array<string, string>      $cookies
     */
    private function buildRequest(
        string $method,
        string $controller,
        string $action,
        array $headers = [],
        ?array $parsedBody = null,
        array $cookies = [],
        ?string $sessionId = self::TEST_SID,
    ): ServerRequestInterface {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn($method);
        $request
            ->method('getAttribute')
            ->willReturnCallback(static function ($name) use ($controller, $action, $sessionId) {
                return match ($name) {
                    Constant::ATTR_CLASSNAME => $controller,
                    Constant::ATTR_METHOD => $action,
                    CsrfConstant::SESSION_REQUEST_ATTRIBUTE => $sessionId,
                    default => null,
                };
            });
        $request
            ->method('getHeaderLine')
            ->willReturnCallback(static function ($name) use ($headers) {
                return $headers[$name] ?? '';
            });
        $request->method('getParsedBody')->willReturn($parsedBody);
        $request->method('getCookieParams')->willReturn($cookies);
        $request->method('withAttribute')->willReturnSelf();
        return $request;
    }

    private function expectingHandler(int $callCount = 1): RequestHandlerInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(static::exactly($callCount))->method('handle')->willReturn($response);
        return $handler;
    }

    private function neverCalledHandler(): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(static::never())->method('handle');
        return $handler;
    }
}
