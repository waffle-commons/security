<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Container;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface as PsrContainerInterface;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Security\Container\SecureContainer;
use Waffle\Commons\Security\Exception\SecurityException;
use WaffleTests\Commons\Security\Helper\Controller\AllowingController;
use WaffleTests\Commons\Security\Helper\Controller\DenyingController;
use WaffleTests\Commons\Security\Helper\Controller\MisconfiguredVoterController;
use WaffleTests\Commons\Security\Helper\Controller\MissingVoterClassController;
use WaffleTests\Commons\Security\Helper\Controller\UnvotedController;

#[CoversClass(SecureContainer::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecureContainerAnalyzeTest extends TestCase
{
    private function makeContainer(): SecureContainer
    {
        return new SecureContainer(
            inner: $this->createStub(PsrContainerInterface::class),
            security: $this->createStub(SecurityInterface::class),
        );
    }

    public function testAnalyzeNoVotersIsNoOp(): void
    {
        // A successful analyze() with zero #[Voter] attributes simply returns.
        $this->makeContainer()->analyze(UnvotedController::class, 'action');

        // No exception thrown = success.
        $this->expectNotToPerformAssertions();
    }

    public function testAnalyzeWithAllowingVotersSucceeds(): void
    {
        // Both class- and method-level Voter attributes return true → no exception.
        $this->makeContainer()->analyze(AllowingController::class, 'action');

        $this->expectNotToPerformAssertions();
    }

    public function testAnalyzeWithDenyingVoterThrowsSecurityException(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Security Policy Violation');

        $this->makeContainer()->analyze(DenyingController::class, 'action');
    }

    public function testAnalyzeWithMissingVoterClassThrows(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Voter class');

        $this->makeContainer()->analyze(MissingVoterClassController::class, 'action');
    }

    public function testAnalyzeWithVoterNotImplementingInterfaceThrows(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('must implement VoterInterface');

        $this->makeContainer()->analyze(MisconfiguredVoterController::class, 'action');
    }

    public function testAnalyzeWithUnreachableTargetThrows(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('unreachable');

        // Non-existent class triggers ReflectionException → wrapped as SecurityException.
        $this->makeContainer()->analyze('No\\Such\\Class', 'noSuchMethod');
    }

    public function testResetInvokesResetOnEveryResettableService(): void
    {
        $resettable = new class implements \Waffle\Commons\Contracts\Service\ResettableInterface {
            public int $resetCount = 0;

            #[\Override]
            public function reset(): void
            {
                $this->resetCount++;
            }
        };

        // A plain object that is NOT resettable — must be skipped silently.
        $plain = new \stdClass();

        $container = new SecureContainer(
            inner: $this->createStub(PsrContainerInterface::class),
            security: $this->createStub(SecurityInterface::class),
            instances: [$resettable, $plain],
        );

        $container->reset();

        static::assertSame(1, $resettable->resetCount);
    }

    public function testGetRethrowsSecurityExceptionInterfaceUnwrapped(): void
    {
        $securityException = new class('denied') extends \RuntimeException implements
            \Waffle\Commons\Contracts\Security\Exception\SecurityExceptionInterface {
            #[\Override]
            public function serialize(): array
            {
                return ['message' => $this->getMessage(), 'code' => $this->getCode()];
            }
        };

        $inner = $this->createMock(PsrContainerInterface::class);
        $inner->method('get')->willReturn(new \stdClass());

        $security = $this->createMock(SecurityInterface::class);
        $security->method('analyze')->willThrowException($securityException);

        $container = new SecureContainer(inner: $inner, security: $security);

        try {
            $container->get('svc');
            static::fail('Expected SecurityExceptionInterface to be rethrown.');
        } catch (\Throwable $caught) {
            // The SecurityException must NOT be wrapped — get() rethrows it identically.
            static::assertSame($securityException, $caught);
        }
    }

    public function testGetWrapsGenericThrowableAsContainerException(): void
    {
        $inner = $this->createMock(PsrContainerInterface::class);
        $inner->method('get')->willThrowException(new \LogicException('unexpected'));

        $container = new SecureContainer(inner: $inner, security: $this->createStub(SecurityInterface::class));

        $this->expectException(\Waffle\Commons\Security\Exception\ContainerException::class);
        $this->expectExceptionMessage('unexpected');

        $container->get('svc');
    }
}
