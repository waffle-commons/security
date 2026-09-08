<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Resolver;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Contracts\Security\SubjectResolverInterface;

/**
 * Concrete resolver for routes carrying no resource: always resolves null, so
 * voting must fall back to the request-shaped subject (SEC-05 contract).
 */
final readonly class NullSubjectResolver implements SubjectResolverInterface
{
    #[\Override]
    public function resolve(ServerRequestInterface $request): mixed
    {
        return null;
    }
}
