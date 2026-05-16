<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Csrf;

use DateInterval;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Contracts\Cache\CacheInterface;
use Waffle\Commons\Security\Csrf\CsrfToken;
use Waffle\Commons\Security\Csrf\CsrfTokenManager;

#[CoversClass(CsrfTokenManager::class)]
#[CoversClass(CsrfToken::class)]
final class CsrfTokenManagerTest extends TestCase
{
    public function testIssueProducesUrlSafeRandomTokenAndStoresIt(): void
    {
        $cache = $this->arrayCache();
        $token = new CsrfTokenManager($cache)->issue('form:login');

        static::assertSame('form:login', $token->getId());
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_\-]+$/', $token->getValue());
        static::assertNotNull($token->getExpiresAt());
    }

    public function testIssueWithExplicitTtlOverridesDefault(): void
    {
        $cache = $this->arrayCache();
        $token = new CsrfTokenManager($cache, defaultTtl: 60)->issue('form:login', ttlSeconds: 900);

        $expiresAt = $token->getExpiresAt();
        static::assertNotNull($expiresAt);
        $issuedAt = $token->getIssuedAt();
        $diff = $expiresAt->getTimestamp() - $issuedAt->getTimestamp();
        static::assertSame(900, $diff);
    }

    public function testIssueWithZeroOrNegativeTtlMeansNeverExpires(): void
    {
        $cache = $this->arrayCache();
        $token = new CsrfTokenManager($cache)->issue('eternal', ttlSeconds: 0);
        static::assertNull($token->getExpiresAt());
    }

    public function testValidateAcceptsFreshlyIssuedToken(): void
    {
        $cache = $this->arrayCache();
        $manager = new CsrfTokenManager($cache);
        $token = $manager->issue('form:login');

        static::assertTrue($manager->validate('form:login', $token->getValue()));
    }

    public function testValidateRejectsMismatch(): void
    {
        $cache = $this->arrayCache();
        $manager = new CsrfTokenManager($cache);
        $manager->issue('form:login');

        static::assertFalse($manager->validate('form:login', 'forged-value'));
    }

    public function testValidateReturnsFalseForUnknownId(): void
    {
        $manager = new CsrfTokenManager($this->arrayCache());
        static::assertFalse($manager->validate('never-issued', 'any'));
    }

    public function testValidateReturnsFalseAndDeletesExpiredEntry(): void
    {
        $cache = $this->arrayCache();
        $manager = new CsrfTokenManager($cache);

        // Bypass `issue()` so we can construct an already-expired payload.
        $reflection = new \ReflectionClass(CsrfTokenManager::class);
        $keyForMethod = $reflection->getMethod('keyFor');
        $key = $keyForMethod->invoke($manager, 'stale');

        $cache->set($key, [
            'id' => 'stale',
            'value' => 'old',
            'issued_at' => new \DateTimeImmutable('-2 hours')->format(\DateTimeImmutable::ATOM),
            'expires_at' => new \DateTimeImmutable('-1 hour')->format(\DateTimeImmutable::ATOM),
        ]);

        static::assertFalse($manager->validate('stale', 'old'));
        static::assertFalse($cache->has($key), 'expired entry must be purged after validation attempt');
    }

    public function testHasValidReflectsCacheState(): void
    {
        $cache = $this->arrayCache();
        $manager = new CsrfTokenManager($cache);

        static::assertFalse($manager->hasValid('form:login'));
        $manager->issue('form:login');
        static::assertTrue($manager->hasValid('form:login'));
    }

    public function testRefreshIssuesNewTokenAndInvalidatesOld(): void
    {
        $cache = $this->arrayCache();
        $manager = new CsrfTokenManager($cache);

        $first = $manager->issue('form:login');
        $second = $manager->refresh('form:login');

        static::assertNotSame($first->getValue(), $second->getValue());
        static::assertFalse($manager->validate('form:login', $first->getValue()));
        static::assertTrue($manager->validate('form:login', $second->getValue()));
    }

    public function testRevokeRemovesStoredToken(): void
    {
        $cache = $this->arrayCache();
        $manager = new CsrfTokenManager($cache);
        $manager->issue('form:login');

        $manager->revoke('form:login');
        static::assertFalse($manager->hasValid('form:login'));
    }

    public function testLoadRejectsMalformedPayloads(): void
    {
        $cache = $this->arrayCache();
        $manager = new CsrfTokenManager($cache);

        $reflection = new \ReflectionClass(CsrfTokenManager::class);
        $keyForMethod = $reflection->getMethod('keyFor');
        $key = $keyForMethod->invoke($manager, 'corrupt');

        // Missing required keys → load() returns null → validate() returns false.
        $cache->set($key, ['something' => 'else']);
        static::assertFalse($manager->validate('corrupt', 'anything'));

        // Non-array payload → same result.
        $cache->set($key, 'not-an-array');
        static::assertFalse($manager->validate('corrupt', 'anything'));

        // Unparsable issued_at → reject.
        $cache->set($key, [
            'id' => 'corrupt',
            'value' => 'v',
            'issued_at' => 'not-a-date',
            'expires_at' => null,
        ]);
        static::assertFalse($manager->validate('corrupt', 'v'));
    }

    public function testLoadGracefullyHandlesInvalidExpiresAtString(): void
    {
        $cache = $this->arrayCache();
        $manager = new CsrfTokenManager($cache);

        $reflection = new \ReflectionClass(CsrfTokenManager::class);
        $keyForMethod = $reflection->getMethod('keyFor');
        $key = $keyForMethod->invoke($manager, 'partial');

        $cache->set($key, [
            'id' => 'partial',
            'value' => 'v',
            'issued_at' => new \DateTimeImmutable()->format(\DateTimeImmutable::ATOM),
            'expires_at' => 'not-a-date',
        ]);

        // Unparsable expires_at → treated as never-expires, validate succeeds.
        static::assertTrue($manager->validate('partial', 'v'));
    }

    /**
     * Minimal in-memory CacheInterface stub. Reused across tests to avoid pulling
     * in waffle-commons/cache as a require-dev (agnosticism rule).
     */
    private function arrayCache(): CacheInterface
    {
        return new class implements CacheInterface {
            /** @var array<string, mixed> */
            private array $store = [];

            #[\Override]
            public function get(string $key, mixed $default = null): mixed
            {
                return $this->store[$key] ?? $default;
            }

            #[\Override]
            public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
            {
                $this->store[$key] = $value;
                return true;
            }

            #[\Override]
            public function delete(string $key): bool
            {
                unset($this->store[$key]);
                return true;
            }

            #[\Override]
            public function clear(): bool
            {
                $this->store = [];
                return true;
            }

            #[\Override]
            public function getMultiple(iterable $keys, mixed $default = null): iterable
            {
                $out = [];
                foreach ($keys as $k) {
                    $out[$k] = $this->store[$k] ?? $default;
                }
                return $out;
            }

            #[\Override]
            public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
            {
                foreach ($values as $k => $v) {
                    $this->store[(string) $k] = $v;
                }
                return true;
            }

            #[\Override]
            public function deleteMultiple(iterable $keys): bool
            {
                foreach ($keys as $k) {
                    unset($this->store[$k]);
                }
                return true;
            }

            #[\Override]
            public function has(string $key): bool
            {
                return array_key_exists($key, $this->store);
            }
        };
    }
}
