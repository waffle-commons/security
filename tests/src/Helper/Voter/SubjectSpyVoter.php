<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Voter;

use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Security\VoterInterface;
use Waffle\Commons\Contracts\Service\ResettableInterface;

/**
 * Concrete spy voter (never an expectation-less mock): records the exact
 * $subject the SecureContainer threads into decide(), so middleware tests can
 * prove a caller-resolved entity reaches the decision point (SEC-05).
 *
 * Declares ResettableInterface DIRECTLY: the recorded subject is deliberate
 * per-run state, released via reset() (worker-safety taxonomy).
 */
final class SubjectSpyVoter implements VoterInterface, ResettableInterface
{
    public bool $called = false;

    public mixed $seenSubject = null;

    #[\Override]
    public function decide(SecurityContextInterface $ctx, mixed $subject = null): bool
    {
        $this->called = true;
        $this->seenSubject = $subject;

        return true;
    }

    #[\Override]
    public function reset(): void
    {
        $this->called = false;
        $this->seenSubject = null;
    }
}
