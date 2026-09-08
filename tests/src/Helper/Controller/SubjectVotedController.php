<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Attribute\Voter;
use WaffleTests\Commons\Security\Helper\Voter\SubjectSpyVoter;

/**
 * Controller whose action is gated by the subject-recording spy voter —
 * fixture proving what the middleware hands to the decision phase (SEC-05).
 */
final class SubjectVotedController
{
    #[Voter(SubjectSpyVoter::class)]
    public function show(): void {}
}
