<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Voter;

use Waffle\Commons\Contracts\Security\VoterInterface;

final class DenyAllVoter implements VoterInterface
{
    #[\Override]
    public function decide(): bool
    {
        return false;
    }
}
