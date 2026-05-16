<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\Voter;

final class MissingVoterClassController
{
    // Intentionally references a class that does not exist; exercises the SecureContainer
    // "Voter class not found" guard.
    #[Voter('NonExistent\\Voter\\Class')]
    public function action(): void {}
}
