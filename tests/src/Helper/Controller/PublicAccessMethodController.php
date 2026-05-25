<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\PublicAccess;

/**
 * Mixed-policy controller: one action is explicitly public, its sibling is
 * unprotected and MUST still be denied under the fail-closed default.
 */
final class PublicAccessMethodController
{
    #[PublicAccess]
    public function publicAction(): void {}

    public function defaultAction(): void {}
}
