<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Exception;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Security\Exception\SecurityException;

#[CoversClass(SecurityException::class)]
#[AllowMockObjectsWithoutExpectations]
class SecurityExceptionCoverageTest extends TestCase
{
    public function testSerializeReturnsArray(): void
    {
        $exception = new SecurityException('Test Message', 123);
        $expected = [
            'message' => 'Test Message',
            'code' => 123,
        ];

        static::assertSame($expected, $exception->serialize());
    }
}
