<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\Voter;
use WaffleTests\Commons\Security\Helper\Voter\NotAVoter;

final class MisconfiguredVoterController
{
    #[Voter(NotAVoter::class)]
    public function action(): void {}
}
