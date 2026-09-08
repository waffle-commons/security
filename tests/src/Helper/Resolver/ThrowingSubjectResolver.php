<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Resolver;

use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Waffle\Commons\Contracts\Security\SubjectResolverInterface;
use Waffle\Commons\Contracts\Service\ResettableInterface;

/**
 * Concrete counting spy resolver simulating a failed subject resolution
 * (unknown id, backend error): on a VOTED route the SecureContainer MUST treat
 * the throw as a fail-closed denial, never as a silent null fallback — and on
 * a #[PublicAccess] route with zero voters it must NEVER be invoked at all
 * (the $invocations counter proves it), so a stale link can't 403 a public
 * page (SEC-05).
 *
 * Declares ResettableInterface DIRECTLY: the invocation counter is deliberate
 * per-run state, released via reset() (worker-safety taxonomy).
 */
final class ThrowingSubjectResolver implements SubjectResolverInterface, ResettableInterface
{
    public const string FAILURE_MESSAGE = 'entity lookup failed';

    public int $invocations = 0;

    #[\Override]
    public function resolve(ServerRequestInterface $request): mixed
    {
        $this->invocations++;

        throw new RuntimeException(self::FAILURE_MESSAGE);
    }

    #[\Override]
    public function reset(): void
    {
        $this->invocations = 0;
    }
}
