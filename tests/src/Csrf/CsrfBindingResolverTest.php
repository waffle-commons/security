<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Csrf;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Contracts\Auth\Constant as AuthConstant;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;
use Waffle\Commons\Security\Csrf\CsrfBindingResolver;

#[CoversClass(CsrfBindingResolver::class)]
final class CsrfBindingResolverTest extends TestCase
{
    public function testBindsToAuthenticatedSubjectWhenPresent(): void
    {
        $request = $this->requestWith(identity: $this->identity('user-42'), sessionId: 'sid-value');

        static::assertSame('auth:user-42', CsrfBindingResolver::resolve($request));
    }

    public function testAuthenticatedSubjectTakesPrecedenceOverAnonymousSid(): void
    {
        $request = $this->requestWith(identity: $this->identity('user-7'), sessionId: 'anon-sid');

        static::assertSame('auth:user-7', CsrfBindingResolver::resolve($request));
    }

    public function testBindsToAnonymousSidWhenNoIdentity(): void
    {
        $request = $this->requestWith(identity: null, sessionId: 'anon-sid-xyz');

        static::assertSame('anon:anon-sid-xyz', CsrfBindingResolver::resolve($request));
    }

    public function testFallsBackToAnonymousWhenIdentitySubjectIsEmpty(): void
    {
        $request = $this->requestWith(identity: $this->identity(''), sessionId: 'fallback-sid');

        static::assertSame('anon:fallback-sid', CsrfBindingResolver::resolve($request));
    }

    public function testReturnsNullWhenNeitherAvailable(): void
    {
        $request = $this->requestWith(identity: null, sessionId: null);

        static::assertNull(CsrfBindingResolver::resolve($request));
    }

    public function testReturnsNullWhenSidIsNotAString(): void
    {
        $request = $this->requestWith(identity: null, sessionId: 12_345);

        static::assertNull(CsrfBindingResolver::resolve($request));
    }

    private function requestWith(?UserIdentityInterface $identity, mixed $sessionId): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request
            ->method('getAttribute')
            ->willReturnCallback(static function (string $name) use ($identity, $sessionId): mixed {
                return match ($name) {
                    AuthConstant::REQUEST_ATTRIBUTE => $identity,
                    CsrfConstant::SESSION_REQUEST_ATTRIBUTE => $sessionId,
                    default => null,
                };
            });

        return $request;
    }

    private function identity(string $subject): UserIdentityInterface
    {
        return new class($subject) implements UserIdentityInterface {
            public function __construct(
                private string $sub,
            ) {}

            public string $subject {
                get => $this->sub;
            }

            public ?string $email {
                get => null;
            }

            public array $roles {
                get => [];
            }

            public array $claims {
                get => [];
            }
        };
    }
}
