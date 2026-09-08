<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Container;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Contracts\Security\SubjectResolverInterface;
use Waffle\Commons\Security\Container\SecureContainer;
use Waffle\Commons\Security\Exception\SecurityException;
use WaffleTests\Commons\Security\Helper\Controller\PublicAccessMethodController;
use WaffleTests\Commons\Security\Helper\Controller\SubjectVotedController;
use WaffleTests\Commons\Security\Helper\Entity\OwnedResource;
use WaffleTests\Commons\Security\Helper\InstanceContainer;
use WaffleTests\Commons\Security\Helper\Resolver\NullSubjectResolver;
use WaffleTests\Commons\Security\Helper\Resolver\StubSubjectResolver;
use WaffleTests\Commons\Security\Helper\Resolver\ThrowingSubjectResolver;
use WaffleTests\Commons\Security\Helper\Voter\SubjectSpyVoter;

/**
 * SEC-05 subject resolution lifecycle, now owned by the SecureContainer:
 * ctor-injected resolver, resolved LAZILY and only when voter discovery finds
 * a non-empty voter list — #[PublicAccess] actions with zero voters never
 * invoke it, an explicit $resolvedSubject overrides it, and a resolver throw
 * on a voted route is a fail-closed 403 (previous chained).
 */
#[CoversClass(SecureContainer::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecureContainerSubjectResolutionTest extends TestCase
{
    private function makeContainer(SubjectSpyVoter $spy, ?SubjectResolverInterface $resolver = null): SecureContainer
    {
        return new SecureContainer(
            inner: new InstanceContainer([SubjectSpyVoter::class => $spy]),
            security: $this->createStub(SecurityInterface::class),
            securityContext: $this->createStub(SecurityContextInterface::class),
            subjectResolver: $resolver,
        );
    }

    private function makeRequest(): ServerRequestInterface
    {
        return $this->createStub(ServerRequestInterface::class);
    }

    public function testCtorResolverSubjectReachesTheVoter(): void
    {
        // The resolver hydrates a domain entity; the very same instance must
        // reach the voter as $subject (object-level IDOR decision target).
        $entity = new OwnedResource(ownerId: 'u42');
        $spy = new SubjectSpyVoter();
        $container = $this->makeContainer($spy, new StubSubjectResolver($entity));

        $container->analyze(SubjectVotedController::class, 'show', $this->makeRequest());

        static::assertTrue($spy->called);
        static::assertSame($entity, $spy->seenSubject);
    }

    public function testResolverIsNeverInvokedForPublicActionsWithZeroVoters(): void
    {
        // THE regression test for the false-403 finding: on a #[PublicAccess]
        // action with zero voters, the subject is never consulted (the voter
        // loop runs zero iterations), so the resolver must never run — a
        // throwing resolver (stale link, unknown id) must not deny a public
        // route, and public routes must not pay the hydration cost.
        $resolver = new ThrowingSubjectResolver();
        $container = $this->makeContainer(new SubjectSpyVoter(), $resolver);

        $container->analyze(PublicAccessMethodController::class, 'publicAction', $this->makeRequest());

        static::assertSame(0, $resolver->invocations);
    }

    public function testResolverFailureOnVotedRouteIsFailClosed(): void
    {
        // On a VOTED route a resolver throw becomes a 403 SecurityException
        // (previous chained), and the voter is never consulted.
        $resolver = new ThrowingSubjectResolver();
        $spy = new SubjectSpyVoter();
        $container = $this->makeContainer($spy, $resolver);

        try {
            $container->analyze(SubjectVotedController::class, 'show', $this->makeRequest());
            static::fail('Expected a fail-closed SecurityException, none was thrown.');
        } catch (SecurityException $denied) {
            static::assertSame(403, $denied->getCode());
            static::assertStringContainsString('fail-closed', $denied->getMessage());
            static::assertStringContainsString(ThrowingSubjectResolver::FAILURE_MESSAGE, $denied->getMessage());
            static::assertInstanceOf(RuntimeException::class, $denied->getPrevious());
            static::assertSame(1, $resolver->invocations);
            static::assertFalse($spy->called);
        }
    }

    public function testExplicitResolvedSubjectOverridesTheCtorResolver(): void
    {
        // An explicitly supplied $resolvedSubject takes precedence: the ctor
        // resolver must not even be invoked (it would throw AND count here).
        $entity = new OwnedResource(ownerId: 'u42');
        $resolver = new ThrowingSubjectResolver();
        $spy = new SubjectSpyVoter();
        $container = $this->makeContainer($spy, $resolver);

        $container->analyze(SubjectVotedController::class, 'show', $this->makeRequest(), $entity);

        static::assertSame(0, $resolver->invocations);
        static::assertTrue($spy->called);
        static::assertSame($entity, $spy->seenSubject);
    }

    public function testNoResolverKeepsRequestShapedVoting(): void
    {
        // Without any resolver wired, behaviour is unchanged: the voter
        // receives the bare PSR-7 request as $subject.
        $spy = new SubjectSpyVoter();
        $request = $this->makeRequest();

        $this->makeContainer($spy)->analyze(SubjectVotedController::class, 'show', $request);

        static::assertTrue($spy->called);
        static::assertSame($request, $spy->seenSubject);
    }

    public function testNullResolvingResolverFallsBackToTheRequest(): void
    {
        // A resolver that finds no resource for the route resolves null: the
        // voter must then receive the PSR-7 request, exactly as without any
        // resolver wired (backwards-compatible fallback).
        $spy = new SubjectSpyVoter();
        $request = $this->makeRequest();

        $this->makeContainer($spy, new NullSubjectResolver())->analyze(SubjectVotedController::class, 'show', $request);

        static::assertTrue($spy->called);
        static::assertSame($request, $spy->seenSubject);
    }
}
