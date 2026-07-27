<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Voter;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Security\VoterInterface;
use WaffleTests\Commons\Security\Helper\Entity\OwnedResource;

/**
 * Ownership voter: grants access only when the authenticated subject owns the
 * targeted resource. Demonstrates the AUTHZ-01 IDOR guarantee — the voter reads
 * the identity from the security context and the resource owner from $subject,
 * threaded in by the SecureContainer.
 *
 * SEC-05: $subject is a resolved {@see OwnedResource} when a caller supplied
 * one (true object-level IDOR), falling back to reading the request attribute
 * when only the request is available — the same voter serves both shapes.
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

        $owner = match (true) {
            $subject instanceof OwnedResource => $subject->ownerId,
            $subject instanceof ServerRequestInterface => $subject->getAttribute('ownerId'),
            default => null,
        };

        return is_string($owner) && hash_equals($identity->subject, $owner);
    }
}
