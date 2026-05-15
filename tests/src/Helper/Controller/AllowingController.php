<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\Voter;
use WaffleTests\Commons\Security\Helper\Voter\AllowAllVoter;

#[Voter(AllowAllVoter::class)]
final class AllowingController
{
    #[Voter(AllowAllVoter::class)]
    public function action(): void {}
}
