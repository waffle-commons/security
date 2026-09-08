<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper;

use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use RuntimeException;

/**
 * Minimal PSR-11 test double seeded with pre-built instances, so a test can
 * hold the very object (e.g. a spy voter) the SecureContainer will resolve —
 * unlike {@see AutowiringContainer}, which returns a fresh instance per get().
 */
final class InstanceContainer implements ContainerInterface
{
    /**
     * @param array<class-string, object> $instances
     */
    public function __construct(
        private readonly array $instances,
    ) {}

    #[\Override]
    public function get(string $id): object
    {
        return (
            $this->instances[$id] ?? throw new class(sprintf('No entry for "%s".', $id)) extends
                RuntimeException implements NotFoundExceptionInterface {}
        );
    }

    #[\Override]
    public function has(string $id): bool
    {
        return array_key_exists($id, $this->instances);
    }
}
