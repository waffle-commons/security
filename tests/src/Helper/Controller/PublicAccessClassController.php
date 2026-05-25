<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\PublicAccess;

/**
 * Controller intentionally exempt from authorization via a class-level
 * `#[PublicAccess]` attribute. Used to exercise SEC-02 fail-closed bypass.
 */
#[PublicAccess]
final class PublicAccessClassController
{
    public function action(): void {}
}
