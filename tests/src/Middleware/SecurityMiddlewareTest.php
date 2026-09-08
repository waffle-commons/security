<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Middleware;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Constant\Constant;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Contracts\Security\SubjectResolverInterface;
use Waffle\Commons\Security\Container\SecureContainer;
use Waffle\Commons\Security\Exception\SecurityException;
use Waffle\Commons\Security\Middleware\SecurityMiddleware;
use WaffleTests\Commons\Security\Helper\AutowiringContainer;
use WaffleTests\Commons\Security\Helper\Controller\AllowingController;
use WaffleTests\Commons\Security\Helper\Controller\DenyingController;
use WaffleTests\Commons\Security\Helper\Controller\SubjectVotedController;
use WaffleTests\Commons\Security\Helper\InstanceContainer;
use WaffleTests\Commons\Security\Helper\Resolver\ThrowingSubjectResolver;
use WaffleTests\Commons\Security\Helper\Voter\SubjectSpyVoter;

#[CoversClass(SecurityMiddleware::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecurityMiddlewareTest extends TestCase
{
    private function makeContainer(): SecureContainer
    {
        return new SecureContainer(
            inner: new AutowiringContainer(),
            security: $this->createStub(SecurityInterface::class),
            securityContext: $this->createStub(SecurityContextInterface::class),
        );
    }

    /**
     * SecureContainer whose inner container resolves the given spy voter, so
     * the test can inspect the exact $subject threaded into decide() (SEC-05).
     */
    private function makeSpyContainer(SubjectSpyVoter $spy, ?SubjectResolverInterface $resolver = null): SecureContainer
    {
        return new SecureContainer(
            inner: new InstanceContainer([SubjectSpyVoter::class => $spy]),
            security: $this->createStub(SecurityInterface::class),
            securityContext: $this->createStub(SecurityContextInterface::class),
            subjectResolver: $resolver,
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

    public function testArrayShapedTargetIsNormalisedBackOntoTheRequest(): void
    {
        // Beta6 review follow-up: after unpacking the [Class, method] array
        // shape, the middleware must write the canonical string attributes
        // back onto the request so every downstream consumer — subject
        // resolvers reading the request inside the SecureContainer, later
        // middlewares, the dispatcher — sees one canonical shape.
        $normalised = $this->makeRequest(AllowingController::class, 'action');

        $afterClassnameWrite = $this->createStub(ServerRequestInterface::class);
        $afterClassnameWrite
            ->method('withAttribute')
            ->willReturnCallback(static function (string $name, mixed $value) use (
                $normalised,
            ): ServerRequestInterface {
                static::assertSame(Constant::ATTR_METHOD, $name);
                static::assertSame('action', $value);
                return $normalised;
            });

        $request = $this->createStub(ServerRequestInterface::class);
        $request
            ->method('getAttribute')
            ->willReturnCallback(static fn(string $name): ?array => match ($name) {
                Constant::ATTR_CLASSNAME => [AllowingController::class, 'action'],
                default => null,
            });
        $request
            ->method('withAttribute')
            ->willReturnCallback(static function (string $name, mixed $value) use (
                $afterClassnameWrite,
            ): ServerRequestInterface {
                static::assertSame(Constant::ATTR_CLASSNAME, $name);
                static::assertSame(AllowingController::class, $value);
                return $afterClassnameWrite;
            });

        $response = $this->createStub(ResponseInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->with($normalised)->willReturn($response);

        $middleware = new SecurityMiddleware(secureContainer: $this->makeContainer());
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

    public function testAnalyzeIsCalledWithoutAPreResolvedSubject(): void
    {
        // SEC-05 smoke test: subject resolution moved INTO the SecureContainer,
        // so the middleware must not pre-resolve anything — analyze() receives
        // no $resolvedSubject and the voter falls back to the bare request.
        $spy = new SubjectSpyVoter();
        $middleware = new SecurityMiddleware(secureContainer: $this->makeSpyContainer($spy));
        $request = $this->makeRequest(SubjectVotedController::class, 'show');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->with($request)->willReturn($response);

        static::assertSame($response, $middleware->process($request, $handler));
        static::assertTrue($spy->called);
        static::assertSame($request, $spy->seenSubject);
    }

    public function testContainerResolverFailureIsLoggedAndRethrown(): void
    {
        // SEC-05 fail-closed, middleware side: the resolver now lives inside
        // the SecureContainer; its 403 SecurityException must bubble out of
        // analyze() and flow through the SAME denial-logging path as any voter
        // denial. The voter must not even be consulted.
        $logger = $this->createMock(LoggerInterface::class);
        $logger
            ->expects($this->once())
            ->method('warning')
            ->with(
                static::stringContains('Access denied'),
                static::callback(
                    static fn(array $ctx): bool => (
                        ($ctx['target'] ?? null) === SubjectVotedController::class . '::show'
                    ),
                ),
            );

        $spy = new SubjectSpyVoter();
        $middleware = new SecurityMiddleware(
            secureContainer: $this->makeSpyContainer($spy, new ThrowingSubjectResolver()),
            logger: $logger,
        );
        $request = $this->makeRequest(SubjectVotedController::class, 'show');

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        try {
            $middleware->process($request, $handler);
            static::fail('Expected a fail-closed SecurityException, none was thrown.');
        } catch (SecurityException $denied) {
            static::assertSame(403, $denied->getCode());
            static::assertStringContainsString('fail-closed', $denied->getMessage());
            static::assertFalse($spy->called);
        }
    }
}
