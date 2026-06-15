<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Voter;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Security\VoterInterface;

/**
 * Ownership voter: grants access only when the authenticated subject owns the
 * targeted resource. Demonstrates the AUTHZ-01 IDOR guarantee — the voter reads
 * the identity from the security context and the resource owner from the
 * request, both threaded in by the SecureContainer.
 */
final class OwnerVoter implements VoterInterface
{
    #[\Override]
    public function decide(SecurityContextInterface $ctx, mixed $subject = null): bool
    {
        $identity = $ctx->getIdentity();
        if ($identity === null) {
            return false;
        }

        $owner = $subject instanceof ServerRequestInterface ? $subject->getAttribute('ownerId') : null;

        return is_string($owner) && hash_equals($identity->subject, $owner);
    }
}
