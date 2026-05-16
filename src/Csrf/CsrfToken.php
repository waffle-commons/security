<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Csrf;

use DateTimeImmutable;
use Waffle\Commons\Contracts\Security\Csrf\CsrfTokenInterface;

/**
 * Immutable CSRF token (Phase 6 / RFC-Alpha 6).
 *
 * Tokens are opaque values rotated per logical id (`form:login`, `api:account-deletion`).
 * The opaque `value` is generated with `random_bytes()` and base64url-encoded — see
 * {@see CsrfTokenManager}. This DTO does not produce the value; it simply transports it
 * alongside the issuance/expiry metadata.
 */
final readonly class CsrfToken implements CsrfTokenInterface
{
    public function __construct(
        private string $id,
        private string $value,
        private DateTimeImmutable $issuedAt,
        private ?DateTimeImmutable $expiresAt = null,
    ) {}

    #[\Override]
    public function getId(): string
    {
        return $this->id;
    }

    #[\Override]
    public function getValue(): string
    {
        return $this->value;
    }

    #[\Override]
    public function getIssuedAt(): DateTimeImmutable
    {
        return $this->issuedAt;
    }

    #[\Override]
    public function getExpiresAt(): ?DateTimeImmutable
    {
        return $this->expiresAt;
    }

    #[\Override]
    public function isExpired(?DateTimeImmutable $now = null): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }
        $reference = $now ?? new DateTimeImmutable();
        return $this->expiresAt <= $reference;
    }
}
