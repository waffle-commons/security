<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Csrf;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use SensitiveParameter;
use Waffle\Commons\Contracts\Security\Csrf\Constant as CsrfConstant;
use Waffle\Commons\Contracts\Security\Csrf\CsrfTokenInterface;
use Waffle\Commons\Contracts\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Stateless **signed double-submit** CSRF token manager with anonymous-session
 * binding (Beta-1 / SEC-01 option C).
 *
 * Replaces the cache-backed implementation. The token is a self-validating
 * payload — no cache lookup, no global cache key, no cross-user contamination.
 *
 * Wire format (binary, then base64url-encoded):
 *
 *     nonce (16 bytes) || expiresAt (8 bytes BE uint64) || hmac (32 bytes)
 *
 * `hmac = HMAC-SHA256(nonce || expiresAt || id || sessionId, secret)`.
 *
 * Both the logical `id` AND the per-browser anonymous session id (carried via
 * the `WAFFLE_SID` cookie, published on the request by
 * {@see \Waffle\Commons\Security\Middleware\AnonymousSessionMiddleware}) are
 * folded into the HMAC payload. A token minted for one (id, sessionId) pair
 * cannot validate against any other.
 *
 * Validation:
 *   1. base64url-decode and length-check (`56 bytes` exactly);
 *   2. reject if the embedded `expiresAt` is in the past (zero ⇒ no expiry);
 *   3. recompute HMAC over `(nonce || expiresAt || id || sessionId)`;
 *   4. `hash_equals()` against the supplied HMAC.
 *
 * **Stateless guarantee:** no instance state lives between requests; no I/O.
 */
final readonly class CsrfTokenManager implements CsrfTokenManagerInterface
{
    private const string HMAC_ALGO = 'sha256';
    private const int NONCE_BYTES = 16;
    private const int TIMESTAMP_BYTES = 8;
    private const int HMAC_BYTES = 32;
    private const int PAYLOAD_BYTES = self::NONCE_BYTES + self::TIMESTAMP_BYTES + self::HMAC_BYTES;

    public function __construct(
        #[SensitiveParameter]
        private string $secret,
        private int $defaultTtl = CsrfConstant::DEFAULT_TTL,
    ) {
        if (strlen($this->secret) < CsrfConstant::MIN_SECRET_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'CSRF signing secret must be at least %d bytes; %d provided.',
                CsrfConstant::MIN_SECRET_BYTES,
                strlen($this->secret),
            ));
        }
    }

    #[\Override]
    public function issue(string $id, string $sessionId, ?int $ttlSeconds = null): CsrfTokenInterface
    {
        if ($sessionId === '') {
            throw new InvalidArgumentException('CSRF session id must not be empty.');
        }

        $ttl = $ttlSeconds ?? $this->defaultTtl;
        $now = new DateTimeImmutable();
        $expiresAt = $ttl > 0 ? $now->add(new DateInterval('PT' . $ttl . 'S')) : null;
        $expiresAtTimestamp = $expiresAt?->getTimestamp() ?? 0;

        $nonce = random_bytes(self::NONCE_BYTES);
        $timestampBytes = pack('J', $expiresAtTimestamp);
        $hmac = hash_hmac(self::HMAC_ALGO, $nonce . $timestampBytes . $id . $sessionId, $this->secret, binary: true);

        $value = self::encode($nonce . $timestampBytes . $hmac);

        return new CsrfToken(id: $id, value: $value, issuedAt: $now, expiresAt: $expiresAt);
    }

    #[\Override]
    public function validate(string $id, string $sessionId, string $candidate): bool
    {
        if ($sessionId === '') {
            return false;
        }

        $raw = self::decode($candidate);
        if ($raw === null || strlen($raw) !== self::PAYLOAD_BYTES) {
            return false;
        }

        $nonce = substr($raw, 0, self::NONCE_BYTES);
        $timestampBytes = substr($raw, self::NONCE_BYTES, self::TIMESTAMP_BYTES);
        $providedHmac = substr($raw, self::NONCE_BYTES + self::TIMESTAMP_BYTES);

        /** @var array{1: int} $unpacked */
        $unpacked = unpack('J', $timestampBytes);
        $expiresAtTimestamp = $unpacked[1];

        if ($expiresAtTimestamp !== 0 && $expiresAtTimestamp <= time()) {
            return false;
        }

        $expectedHmac = hash_hmac(
            self::HMAC_ALGO,
            $nonce . $timestampBytes . $id . $sessionId,
            $this->secret,
            binary: true,
        );

        return hash_equals($expectedHmac, $providedHmac);
    }

    #[\Override]
    public function refresh(string $id, string $sessionId): CsrfTokenInterface
    {
        return $this->issue($id, $sessionId);
    }

    #[\Override]
    public function revoke(string $id): void
    {
        // Stateless: individual tokens cannot be revoked without rotating the
        // signing secret. Documented in the interface contract.
    }

    #[\Override]
    public function hasValid(string $id): bool
    {
        // No server-side inventory. Callers MUST issue() rather than rely on this.
        return false;
    }

    private static function encode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private static function decode(string $value): ?string
    {
        $padded = strtr($value, '-_', '+/');
        $padLen = (4 - (strlen($padded) % 4)) % 4;
        $padded .= str_repeat('=', $padLen);
        $decoded = base64_decode($padded, strict: true);
        return $decoded === false ? null : $decoded;
    }
}
