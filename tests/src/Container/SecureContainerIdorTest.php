<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Container;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Security\Container\SecureContainer;
use Waffle\Commons\Security\Exception\SecurityException;
use WaffleTests\Commons\Security\Helper\AutowiringContainer;
use WaffleTests\Commons\Security\Helper\Controller\OwnedResourceController;
use WaffleTests\Commons\Security\Helper\Entity\OwnedResource;
use WaffleTests\Commons\Security\Helper\Identity\FakeIdentity;

/**
 * AUTHZ-01: a context-aware ownership voter must grant the owner and deny any
 * other authenticated subject (IDOR). Proves the voter can now see the identity
 * (via the security context) and the resource owner (via the request), both
 * threaded in by the SecureContainer — impossible under the old `decide(): bool`.
 */
#[CoversClass(SecureContainer::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecureContainerIdorTest extends TestCase
{
    private function makeContainer(string $authenticatedSubject): SecureContainer
    {
        $context = $this->createStub(SecurityContextInterface::class);
        $context->method('getIdentity')->willReturn(new FakeIdentity(subject: $authenticatedSubject));

        return new SecureContainer(
            inner: new AutowiringContainer(),
            security: $this->createStub(SecurityInterface::class),
            securityContext: $context,
        );
    }

    private function requestOwnedBy(string $ownerId): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturnCallback(static fn(string $name): ?string => $name === 'ownerId'
            ? $ownerId
            : null);

        return $request;
    }

    public function testOwnerIsGrantedAccessToTheirOwnResource(): void
    {
        // Subject 'u1' editing the resource owned by 'u1' → granted (no throw).
        $this->makeContainer('u1')->analyze(OwnedResourceController::class, 'edit', $this->requestOwnedBy('u1'));

        $this->expectNotToPerformAssertions();
    }

    public function testNonOwnerIsDeniedCrossOwnerAccess(): void
    {
        // Subject 'u1' editing the resource owned by 'u2' → denied (403 / IDOR).
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(403);

        $this->makeContainer('u1')->analyze(OwnedResourceController::class, 'edit', $this->requestOwnedBy('u2'));
    }

    public function testResolvedSubjectTakesPrecedenceOverRequestForOwnershipDecision(): void
    {
        // SEC-05: a caller-resolved domain entity is now what the voter decides
        // against — true object-level IDOR, not just request-attribute
        // inspection. The request here is (deliberately) owned by a DIFFERENT
        // user than the resolved entity, proving the entity wins, not the
        // request.
        $this->makeContainer('u1')->analyze(
            OwnedResourceController::class,
            'edit',
            $this->requestOwnedBy('u2'),
            new OwnedResource(ownerId: 'u1'),
        );

        $this->expectNotToPerformAssertions();
    }

    public function testResolvedSubjectOwnershipMismatchIsDenied(): void
    {
        // Mirror of the above: the request would have granted access ('u1'
        // owns it per the request), but the resolved entity says 'u2' owns
        // it — the resolved entity must win, so access is denied.
        $this->expectException(SecurityException::class);
        $this->expectExceptionCode(403);

        $this->makeContainer('u1')->analyze(
            OwnedResourceController::class,
            'edit',
            $this->requestOwnedBy('u1'),
            new OwnedResource(ownerId: 'u2'),
        );
    }
}
