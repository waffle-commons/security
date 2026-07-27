<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\PublicAccess;

/**
 * SEC-05 regression: a stray class-level `#[PublicAccess]` (the pre-fix
 * convention) must no longer exempt an unvoted method — the attribute is
 * method-only now, and SecureContainer never inspects class-level placement.
 */
#[PublicAccess]
final class StrayClassLevelPublicAccessController
{
    public function action(): void {}
}
