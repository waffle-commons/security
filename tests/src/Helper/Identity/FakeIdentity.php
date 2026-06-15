<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Identity;

use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * Concrete UserIdentityInterface test double for authorization scenarios.
 */
final class FakeIdentity implements UserIdentityInterface
{
    /**
     * @param list<string>         $roles
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public string $subject = 'anonymous',
        public ?string $email = null,
        public array $roles = [],
        public array $claims = [],
    ) {}
}
