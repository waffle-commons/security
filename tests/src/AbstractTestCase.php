<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security;

use PHPUnit\Framework\TestCase as BaseTestCase;
use Waffle\Commons\Contracts\Config\ConfigInterface;
use Waffle\Commons\Security\Security;

abstract class AbstractTestCase extends BaseTestCase
{
    protected function createAndGetConfig(int $securityLevel = 10): ConfigInterface
    {
        $configMock = $this->createMock(ConfigInterface::class);
        $configMock->expects($this->once())->method('getInt')->willReturn($securityLevel);

        return $configMock;
    }

    protected function createAndGetSecurity(int $level = 10, null|ConfigInterface $config = null): Security
    {
        $configMock = $this->createAndGetConfig(securityLevel: $level);

        return new Security(cfg: $config ?? $configMock);
    }
}
