<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Csrf;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Security\Csrf\CsrfToken;

#[CoversClass(CsrfToken::class)]
final class CsrfTokenTest extends TestCase
{
    public function testExposesAllProperties(): void
    {
        $issuedAt = new DateTimeImmutable('2026-01-01T00:00:00+00:00');
        $expiresAt = new DateTimeImmutable('2026-01-01T01:00:00+00:00');
        $token = new CsrfToken('form:login', 'abc123', $issuedAt, $expiresAt);

        static::assertSame('form:login', $token->getId());
        static::assertSame('abc123', $token->getValue());
        static::assertSame($issuedAt, $token->getIssuedAt());
        static::assertSame($expiresAt, $token->getExpiresAt());
    }

    public function testNullExpiresAtMeansNeverExpires(): void
    {
        $token = new CsrfToken('eternal', 'v', new DateTimeImmutable(), null);

        static::assertNull($token->getExpiresAt());
        static::assertFalse($token->isExpired());
    }

    public function testIsExpiredAgainstReferenceClock(): void
    {
        $token = new CsrfToken(
            'soon',
            'v',
            new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            new DateTimeImmutable('2026-01-01T01:00:00+00:00'),
        );

        static::assertFalse($token->isExpired(new DateTimeImmutable('2026-01-01T00:30:00+00:00')));
        static::assertTrue($token->isExpired(new DateTimeImmutable('2026-01-01T01:00:00+00:00')));
        static::assertTrue($token->isExpired(new DateTimeImmutable('2026-01-01T02:00:00+00:00')));
    }

    public function testIsExpiredDefaultsToCurrentTime(): void
    {
        $token = new CsrfToken('stale', 'v', new DateTimeImmutable('-2 hours'), new DateTimeImmutable('-1 hour'));
        static::assertTrue($token->isExpired());
    }
}
