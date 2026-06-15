<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\Voter;
use WaffleTests\Commons\Security\Helper\Voter\OwnerVoter;

/**
 * Controller whose action is gated by an ownership voter — fixture for the
 * AUTHZ-01 IDOR scenario.
 */
final class OwnedResourceController
{
    #[Voter(OwnerVoter::class)]
    public function edit(): void {}
}
