<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Csrf\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Contracts\Security\Csrf\Exception\CsrfExceptionInterface;
use Waffle\Commons\Security\Csrf\Exception\CsrfException;
use Waffle\Commons\Security\Csrf\Exception\InvalidCsrfTokenException;
use Waffle\Commons\Security\Csrf\Exception\MissingCsrfTokenException;

#[CoversClass(CsrfException::class)]
#[CoversClass(InvalidCsrfTokenException::class)]
#[CoversClass(MissingCsrfTokenException::class)]
final class CsrfExceptionsTest extends TestCase
{
    public function testCsrfExceptionDefaultsTo403(): void
    {
        $e = new CsrfException();
        static::assertSame(403, $e->getCode());
        static::assertSame('CSRF validation failed.', $e->getMessage());
        static::assertInstanceOf(CsrfExceptionInterface::class, $e);
    }

    public function testCsrfExceptionSerializeReturnsMessageAndCode(): void
    {
        $e = new CsrfException(message: 'denied', code: 403);
        static::assertSame(['message' => 'denied', 'code' => 403], $e->serialize());
    }

    public function testInvalidExposesTokenIdAndDefaultMessage(): void
    {
        $e = new InvalidCsrfTokenException(tokenId: 'form:login');
        static::assertSame('form:login', $e->getTokenId());
        static::assertStringContainsString('Invalid CSRF token', $e->getMessage());
        static::assertStringContainsString('form:login', $e->getMessage());
        static::assertSame(403, $e->getCode());
    }

    public function testInvalidAllowsExplicitMessageOverride(): void
    {
        $e = new InvalidCsrfTokenException(tokenId: 'form:login', message: 'custom');
        static::assertSame('custom', $e->getMessage());
    }

    public function testMissingExposesTokenIdAndDefaultMessage(): void
    {
        $e = new MissingCsrfTokenException(tokenId: 'api:delete');
        static::assertSame('api:delete', $e->getTokenId());
        static::assertStringContainsString('Missing CSRF token', $e->getMessage());
        static::assertStringContainsString('api:delete', $e->getMessage());
        static::assertSame(403, $e->getCode());
    }

    public function testMissingAllowsExplicitMessageOverride(): void
    {
        $e = new MissingCsrfTokenException(tokenId: 'api:delete', message: 'custom missing');
        static::assertSame('custom missing', $e->getMessage());
    }
}
