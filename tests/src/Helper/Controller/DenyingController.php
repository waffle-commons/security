<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\Voter;
use WaffleTests\Commons\Security\Helper\Voter\DenyAllVoter;

final class DenyingController
{
    #[Voter(DenyAllVoter::class)]
    public function action(): void {}
}
