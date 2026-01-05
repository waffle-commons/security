<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Container;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface as PsrContainerInterface;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Security\Container\SecureContainer;
use Waffle\Commons\Security\Exception\ContainerException;

#[CoversClass(SecureContainer::class)]
#[AllowMockObjectsWithoutExpectations]
class SecureContainerEdgeCaseTest extends TestCase
{
    public function testSetThrowsExceptionIfInnerContainerDoesNotSupportSet(): void
    {
        // PsrContainerInterface does not have set method.
        // We create an anonymous class implementing ONLY PsrContainerInterface
        $inner = new class implements PsrContainerInterface {
            public function get(string $id)
            {
            }

            public function has(string $id): bool
            {
                return false;
            }
        };

        $security = $this->createMock(SecurityInterface::class);
        $container = new SecureContainer($inner, $security);

        $this->expectException(ContainerException::class);
        $this->expectExceptionMessage("The inner container does not support mutable 'set' operations.");

        $container->set('id', new \stdClass());
    }
}
