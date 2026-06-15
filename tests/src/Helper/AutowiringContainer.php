<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper;

use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use RuntimeException;

/**
 * Minimal PSR-11 test double that autowires any instantiable class-string to a
 * fresh instance, mirroring the real Waffle Container::get() path the
 * SecureContainer relies on to resolve voters (AUTHZ-01) — without a
 * cross-component dependency on the concrete container.
 */
final class AutowiringContainer implements ContainerInterface
{
    #[\Override]
    public function get(string $id): object
    {
        if (!class_exists($id)) {
            throw new class(sprintf('No entry for "%s".', $id)) extends RuntimeException implements
                NotFoundExceptionInterface {};
        }

        return new $id();
    }

    #[\Override]
    public function has(string $id): bool
    {
        return class_exists($id);
    }
}
