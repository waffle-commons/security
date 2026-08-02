<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Resolver;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Contracts\Security\SubjectResolverInterface;

/**
 * Concrete stub resolver returning a fixed, pre-hydrated domain subject —
 * stands in for an application resolver that turns a route `{id}` into an
 * entity (SEC-05).
 */
final readonly class StubSubjectResolver implements SubjectResolverInterface
{
    public function __construct(
        private object $subject,
    ) {}

    #[\Override]
    public function resolve(ServerRequestInterface $request): mixed
    {
        return $this->subject;
    }
}
