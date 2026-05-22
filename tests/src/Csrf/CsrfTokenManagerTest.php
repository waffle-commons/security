<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Csrf;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Security\Csrf\CsrfToken;
use Waffle\Commons\Security\Csrf\CsrfTokenManager;

#[CoversClass(CsrfTokenManager::class)]
#[CoversClass(CsrfToken::class)]
final class CsrfTokenManagerTest extends TestCase
{
    private string $secret;
    private string $sid;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        // 32 random bytes — the minimum the manager accepts. Generated per test
        // so no literal sensitive value lives in source.
        $this->secret = random_bytes(32);
        // Stand-in for the anonymous SID that AnonymousSessionMiddleware would
        // publish on the request in production.
        $this->sid = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public function testConstructorRejectsShortSecret(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 32 bytes');

        new CsrfTokenManager(secret: random_bytes(10));
    }

    public function testIssueProducesUrlSafeBase64TokenAndMetadata(): void
    {
        $token = new CsrfTokenManager($this->secret)->issue('form:login', $this->sid);

        static::assertSame('form:login', $token->getId());
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_\-]+$/', $token->getValue());
        static::assertNotNull($token->getExpiresAt());
    }

    public function testIssueWithExplicitTtlOverridesDefault(): void
    {
        $token = new CsrfTokenManager($this->secret, defaultTtl: 60)->issue('form:login', $this->sid, ttlSeconds: 900);

        $expiresAt = $token->getExpiresAt();
        static::assertNotNull($expiresAt);
        $diff = $expiresAt->getTimestamp() - $token->getIssuedAt()->getTimestamp();
        static::assertSame(900, $diff);
    }

    public function testIssueWithZeroTtlMeansNeverExpires(): void
    {
        $token = new CsrfTokenManager($this->secret)->issue('eternal', $this->sid, ttlSeconds: 0);
        static::assertNull($token->getExpiresAt());
    }

    public function testIssueRejectsEmptySessionId(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('session id must not be empty');

        new CsrfTokenManager($this->secret)->issue('form:login', '');
    }

    public function testValidateAcceptsFreshlyIssuedToken(): void
    {
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('form:login', $this->sid);

        static::assertTrue($manager->validate('form:login', $this->sid, $token->getValue()));
    }

    public function testValidateAcceptsNonExpiringToken(): void
    {
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('eternal', $this->sid, ttlSeconds: 0);

        static::assertTrue($manager->validate('eternal', $this->sid, $token->getValue()));
    }

    public function testValidateRejectsTokenIssuedForDifferentId(): void
    {
        // The id is folded into the HMAC payload, so cross-id replay must fail.
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('form:login', $this->sid);

        static::assertFalse($manager->validate('form:account-deletion', $this->sid, $token->getValue()));
    }

    public function testValidateRejectsTokenIssuedForDifferentSessionId(): void
    {
        // SEC-01 option C: sessionId is folded into the HMAC payload, so a
        // token minted for one browser cannot validate against another.
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('form:login', $this->sid);

        $otherSid = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        static::assertFalse($manager->validate('form:login', $otherSid, $token->getValue()));
    }

    public function testValidateRejectsEmptySessionId(): void
    {
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('form:login', $this->sid);

        static::assertFalse($manager->validate('form:login', '', $token->getValue()));
    }

    public function testValidateRejectsTokenSignedWithDifferentSecret(): void
    {
        $issuer = new CsrfTokenManager($this->secret);
        $token = $issuer->issue('form:login', $this->sid);

        $verifier = new CsrfTokenManager(random_bytes(32));
        static::assertFalse($verifier->validate('form:login', $this->sid, $token->getValue()));
    }

    public function testValidateRejectsExpiredToken(): void
    {
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('form:login', $this->sid, ttlSeconds: 1);

        // Wait past the expiry. 1-second granularity in the wire timestamp.
        sleep(2);

        static::assertFalse($manager->validate('form:login', $this->sid, $token->getValue()));
    }

    public function testValidateRejectsTamperedToken(): void
    {
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('form:login', $this->sid);
        $value = $token->getValue();

        // Flip a single base64url-safe character anywhere past the nonce region.
        $mutated = $value[0] === 'a' ? 'b' . substr($value, 1) : 'a' . substr($value, 1);

        static::assertFalse($manager->validate('form:login', $this->sid, $mutated));
    }

    public function testValidateRejectsTruncatedToken(): void
    {
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('form:login', $this->sid);

        static::assertFalse($manager->validate('form:login', $this->sid, substr($token->getValue(), 0, -4)));
    }

    public function testValidateRejectsCompletelyMalformedInput(): void
    {
        $manager = new CsrfTokenManager($this->secret);

        static::assertFalse($manager->validate('form:login', $this->sid, ''));
        static::assertFalse($manager->validate('form:login', $this->sid, '%%%not-base64%%%'));
        static::assertFalse($manager->validate('form:login', $this->sid, 'short'));
    }

    public function testRefreshIssuesNewToken(): void
    {
        $manager = new CsrfTokenManager($this->secret);

        $first = $manager->issue('form:login', $this->sid);
        $second = $manager->refresh('form:login', $this->sid);

        static::assertNotSame($first->getValue(), $second->getValue());
        // Both remain valid until expiry — there is no server-side inventory.
        static::assertTrue($manager->validate('form:login', $this->sid, $first->getValue()));
        static::assertTrue($manager->validate('form:login', $this->sid, $second->getValue()));
    }

    public function testRevokeIsNoOpInStatelessImplementation(): void
    {
        $manager = new CsrfTokenManager($this->secret);
        $token = $manager->issue('form:login', $this->sid);
        $manager->revoke('form:login');

        // Stateless manager cannot invalidate individual tokens.
        static::assertTrue($manager->validate('form:login', $this->sid, $token->getValue()));
    }

    public function testHasValidAlwaysReturnsFalseInStatelessImplementation(): void
    {
        $manager = new CsrfTokenManager($this->secret);
        $manager->issue('form:login', $this->sid);

        static::assertFalse($manager->hasValid('form:login'));
    }
}
