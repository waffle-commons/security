<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Csrf;

use DateInterval;
use DateTimeImmutable;
use SensitiveParameter;
use Waffle\Commons\Contracts\Cache\CacheInterface;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;
use Waffle\Commons\Contracts\Security\Csrf\CsrfTokenInterface;
use Waffle\Commons\Contracts\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Cache-backed CSRF token manager (Phase 6 / Alpha 6 §6).
 *
 * Tokens are stored as serialized array payloads under a PSR-16 cache key derived
 * from the logical id. The cache backend (Array, File, Redis) is injected — Redis
 * gives cross-worker visibility, File survives restarts, Array is worker-scoped.
 *
 * Constant-time comparison is performed with `hash_equals()` to defeat timing
 * side-channels. Token bytes come from `random_bytes()` (CSPRNG), base64url-encoded
 * so the value is safe to ship in headers, cookies, and form fields without
 * additional escaping.
 *
 * **Stateless guarantee:** no instance state lives between requests. All persistence
 * is delegated to the injected cache.
 */
final class CsrfTokenManager implements CsrfTokenManagerInterface
{
    /** Cache-key namespace prefix — avoids collisions with non-CSRF cache entries. */
    private const string KEY_PREFIX = 'csrf.';

    /** Bytes of entropy per token. 32 bytes ⇒ 256-bit token. */
    private const int TOKEN_BYTES = 32;

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int $defaultTtl = CsrfConstant::DEFAULT_TTL,
    ) {}

    #[\Override]
    public function issue(string $id, ?int $ttlSeconds = null): CsrfTokenInterface
    {
        $ttl = $ttlSeconds ?? $this->defaultTtl;
        $value = $this->generateValue();

        $now = new DateTimeImmutable();
        $expiresAt = $ttl > 0 ? $now->add(new DateInterval('PT' . $ttl . 'S')) : null;

        $token = new CsrfToken(id: $id, value: $value, issuedAt: $now, expiresAt: $expiresAt);
        $this->persist($token, $ttl);

        return $token;
    }

    #[\Override]
    public function validate(string $id, string $candidate): bool
    {
        $stored = $this->load($id);
        if ($stored === null) {
            return false;
        }
        if ($stored->isExpired()) {
            $this->cache->delete($this->keyFor($id));
            return false;
        }
        return hash_equals($stored->getValue(), $candidate);
    }

    #[\Override]
    public function refresh(string $id): CsrfTokenInterface
    {
        $this->revoke($id);
        return $this->issue($id);
    }

    #[\Override]
    public function revoke(string $id): void
    {
        $this->cache->delete($this->keyFor($id));
    }

    #[\Override]
    public function hasValid(string $id): bool
    {
        $stored = $this->load($id);
        return $stored !== null && !$stored->isExpired();
    }

    private function generateValue(): string
    {
        // base64url-encoded 256-bit token: URL/header/cookie safe without escaping.
        return rtrim(strtr(base64_encode(random_bytes(self::TOKEN_BYTES)), '+/', '-_'), '=');
    }

    private function persist(#[SensitiveParameter] CsrfTokenInterface $token, int $ttl): void
    {
        $expiresAt = $token->getExpiresAt();
        $payload = [
            'id' => $token->getId(),
            'value' => $token->getValue(),
            'issued_at' => $token->getIssuedAt()->format(DateTimeImmutable::ATOM),
            'expires_at' => $expiresAt?->format(DateTimeImmutable::ATOM),
        ];
        $this->cache->set($this->keyFor($token->getId()), $payload, $ttl > 0 ? $ttl : null);
    }

    private function load(string $id): ?CsrfTokenInterface
    {
        $raw = $this->cache->get($this->keyFor($id));
        if (!is_array($raw)) {
            return null;
        }

        $value = $raw['value'] ?? null;
        $issuedAtRaw = $raw['issued_at'] ?? null;
        $storedId = $raw['id'] ?? $id;
        $expiresAtRaw = $raw['expires_at'] ?? null;

        if (!is_string($value) || !is_string($issuedAtRaw) || !is_string($storedId)) {
            return null;
        }

        $issuedAt = DateTimeImmutable::createFromFormat(DateTimeImmutable::ATOM, $issuedAtRaw);
        if ($issuedAt === false) {
            return null;
        }

        $expiresAt = null;
        if (is_string($expiresAtRaw)) {
            $parsed = DateTimeImmutable::createFromFormat(DateTimeImmutable::ATOM, $expiresAtRaw);
            $expiresAt = $parsed === false ? null : $parsed;
        }

        return new CsrfToken(id: $storedId, value: $value, issuedAt: $issuedAt, expiresAt: $expiresAt);
    }

    /**
     * Derives a PSR-16-safe cache key for a logical id. Hashing keeps the
     * key length bounded and side-steps reserved characters (`:`, `/`, `\`, …)
     * which user-facing ids like `form:login` may contain.
     */
    private function keyFor(string $id): string
    {
        return self::KEY_PREFIX . substr(hash('sha256', $id), 0, 32);
    }
}
