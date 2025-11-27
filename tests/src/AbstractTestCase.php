<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security;

use PHPUnit\Framework\TestCase as BaseTestCase;
use Waffle\Commons\Contracts\Config\ConfigInterface;
use Waffle\Commons\Security\Security;

abstract class AbstractTestCase extends BaseTestCase
{
    protected string $testConfigDir = APP_ROOT . DIRECTORY_SEPARATOR . APP_CONFIG;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        // Create a temporary config directory for isolated testing
        if (!is_dir($this->testConfigDir)) {
            mkdir($this->testConfigDir, 0o777, true);
        }
    }

    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();
        // Clean up the temporary config directory safely
        $this->cleanupTestConfig();
    }

    protected function cleanupTestConfig(): void
    {
        $dirToDelete = APP_ROOT . DIRECTORY_SEPARATOR . APP_CONFIG;
        if (is_dir($dirToDelete)) {
            $this->recursiveDelete($dirToDelete);
        }
    }

    private function recursiveDelete(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $scanDir = scandir($dir);
        if (!$scanDir) {
            return;
        }
        $items = array_diff($scanDir, ['.', '..']);

        foreach ($items as $item) {
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            is_dir($path) ? $this->recursiveDelete($path) : unlink($path);
        }

        rmdir($dir);
    }

    protected function createAndGetSecurity(int $level = 10, null|ConfigInterface $config = null): Security
    {
        $configMock = $this->createMock(ConfigInterface::class);
        $configMock->expects($this->once())->method('getInt')->willReturn($level);

        return new Security(cfg: $config ?? $configMock);
    }
}
