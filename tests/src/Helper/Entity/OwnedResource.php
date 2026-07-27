<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Entity;

/**
 * A resolved domain entity — the SEC-05 fixture proving voters can decide
 * against a real object instead of only the raw PSR-7 request.
 */
final readonly class OwnedResource
{
    public function __construct(
        public string $ownerId,
    ) {}
}
