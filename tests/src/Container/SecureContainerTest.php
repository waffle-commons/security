<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Container;

use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface as PsrContainerInterface;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Security\Container\SecureContainer;
use Waffle\Commons\Security\Exception\ContainerException;
use Waffle\Commons\Security\Exception\NotFoundException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;

#[AllowMockObjectsWithoutExpectations]
class SecureContainerTest extends TestCase
{
    public function testGetDelegatesToInnerAndAnalyzesSecurity(): void
    {
        $inner = $this->createMock(PsrContainerInterface::class);
        $security = $this->createMock(SecurityInterface::class);
        $service = new \stdClass();

        $inner->expects($this->once())->method('get')->with('service_id')->willReturn($service);

        $security->expects($this->once())->method('analyze')->with($service);

        $container = new SecureContainer($inner, $security);

        static::assertSame($service, $container->get('service_id'));
    }

    public function testGetThrowsNotFoundException(): void
    {
        $inner = $this->createMock(PsrContainerInterface::class);
        $security = $this->createMock(SecurityInterface::class);

        $inner
            ->method('get')
            ->willThrowException(new class extends \Exception implements \Psr\Container\NotFoundExceptionInterface {});

        $container = new SecureContainer($inner, $security);

        $this->expectException(NotFoundException::class);
        $container->get('missing_service');
    }

    public function testGetThrowsContainerException(): void
    {
        $inner = $this->createMock(PsrContainerInterface::class);
        $security = $this->createMock(SecurityInterface::class);

        $inner
            ->method('get')
            ->willThrowException(new class extends \Exception implements \Psr\Container\ContainerExceptionInterface {});

        $container = new SecureContainer($inner, $security);

        $this->expectException(ContainerException::class);
        $container->get('error_service');
    }

    public function testHasDelegatesToInner(): void
    {
        $inner = $this->createMock(PsrContainerInterface::class);
        $security = $this->createMock(SecurityInterface::class);

        $inner->expects($this->once())->method('has')->with('service_id')->willReturn(true);

        $container = new SecureContainer($inner, $security);

        static::assertTrue($container->has('service_id'));
    }

    public function testSetDelegatesToInnerIfSupported(): void
    {
        $service = new \stdClass();

        // Use anonymous class to simulate container with set method
        $inner = new class($service) implements PsrContainerInterface {
            public bool $setCalled = false;

            public function __construct(
                private object $expectedService,
            ) {}

            #[\Override]
            public function get(string $id): mixed
            {
                return null;
            }

            #[\Override]
            public function has(string $id): bool
            {
                return false;
            }

            public function set(string $id, object|callable|string $concrete): void
            {
                if ($id === 'service_id' && $concrete === $this->expectedService) {
                    $this->setCalled = true;
                }
            }
        };

        $security = $this->createMock(SecurityInterface::class);
        $container = new SecureContainer($inner, $security);

        $container->set('service_id', $service);

        static::assertTrue($inner->setCalled);
    }

    public function testSetThrowsExceptionIfInnerDoesNotSupportSet(): void
    {
        $inner = $this->createMock(PsrContainerInterface::class); // No set method
        $security = $this->createMock(SecurityInterface::class);

        $container = new SecureContainer($inner, $security);

        $this->expectException(ContainerException::class);
        $this->expectExceptionMessage("The inner container does not support mutable 'set' operations.");

        $container->set('service_id', new \stdClass());
    }
}
