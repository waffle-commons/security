<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Cors;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Security\Cors\CorsPolicy;

#[CoversClass(CorsPolicy::class)]
final class CorsPolicyTest extends TestCase
{
    public function testEmptyAllowListRejectsEveryOrigin(): void
    {
        $policy = new CorsPolicy();

        static::assertFalse($policy->allowsOrigin('https://app.example.com'));
        static::assertFalse($policy->allowsOrigin(''));
    }

    public function testExactOriginIsAllowedAndOthersRejected(): void
    {
        $policy = new CorsPolicy(allowedOrigins: ['https://app.example.com']);

        static::assertTrue($policy->allowsOrigin('https://app.example.com'));
        static::assertFalse($policy->allowsOrigin('https://evil.example.com'));
        // Scheme/port are part of the origin — a mismatch is rejected.
        static::assertFalse($policy->allowsOrigin('http://app.example.com'));
    }

    public function testWildcardAllowsAnyOriginWithoutCredentials(): void
    {
        $policy = new CorsPolicy(allowedOrigins: ['*']);

        static::assertTrue($policy->allowsOrigin('https://anything.example.com'));
        static::assertFalse($policy->allowsOrigin(''));
    }

    public function testWildcardWithCredentialsIsRejectedAtConstruction(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('wildcard');

        new CorsPolicy(allowedOrigins: ['*'], allowCredentials: true);
    }

    public function testCredentialedExactOriginIsAllowed(): void
    {
        $policy = new CorsPolicy(allowedOrigins: ['https://app.example.com'], allowCredentials: true);

        static::assertTrue($policy->allowsOrigin('https://app.example.com'));
        static::assertTrue($policy->allowCredentials);
    }

    public function testExposesConfiguredDefaults(): void
    {
        $policy = new CorsPolicy();

        static::assertContains('GET', $policy->allowedMethods);
        static::assertContains('Content-Type', $policy->allowedHeaders);
        static::assertSame(600, $policy->maxAge);
        static::assertFalse($policy->allowCredentials);
    }
}
