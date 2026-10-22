<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\RateLimit;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Waffle\Commons\Contracts\RateLimit\Exception\StateStorageExceptionInterface;
use Waffle\Commons\Contracts\RateLimit\LimiterStateStorageInterface;
use Waffle\Commons\Contracts\RateLimit\RateLimitDecision;
use Waffle\Commons\Contracts\RateLimit\TokenBucket;
use Waffle\Commons\Contracts\Telemetry\Metrics\MetricsRegistryInterface;
use Waffle\Commons\Security\RateLimit\RateLimiter;
use Waffle\Commons\Security\RateLimit\StorageFailureMode;

#[CoversClass(RateLimiter::class)]
final class RateLimiterTest extends TestCase
{
    public function testDelegatesToTheSharedStorage(): void
    {
        $bucket = new TokenBucket(10, 60);
        $decision = new RateLimitDecision(true, 10, 9, 6);
        $storage = $this->createMock(LimiterStateStorageInterface::class);
        $storage->expects($this->once())->method('consume')->with('ip:203.0.113.7', $bucket, 1)->willReturn($decision);

        static::assertSame($decision, new RateLimiter($storage, $bucket)->consume('ip:203.0.113.7'));
    }

    public function testAnOutageLetsTheCallThroughUnenforcedByDefault(): void
    {
        $decision = new RateLimiter($this->brokenStorage(), new TokenBucket(10, 60))->consume('k');

        static::assertTrue($decision->allowed);
        static::assertFalse($decision->enforced);
    }

    public function testAnOutageRefusesTheCallWhenClosed(): void
    {
        $decision = new RateLimiter(
            $this->brokenStorage(),
            new TokenBucket(10, 60),
            StorageFailureMode::Closed,
        )->consume('k');

        static::assertFalse($decision->allowed);
        static::assertFalse($decision->enforced);
        static::assertSame(1, $decision->retryAfterSeconds);
    }

    public function testAnOutageIsCountedByFailureModeOnly(): void
    {
        $metrics = $this->createMock(MetricsRegistryInterface::class);
        $metrics->expects($this->once())->method('increment')->with(RateLimiter::STORAGE_ERRORS_METRIC, 1.0, [
            'mode' => 'closed',
        ]);

        new RateLimiter(
            $this->brokenStorage(),
            new TokenBucket(10, 60),
            StorageFailureMode::Closed,
            metrics: $metrics,
        )->consume('ip:203.0.113.7');
    }

    public function testRefusesAnEmptyKey(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RateLimiter($this->createStub(LimiterStateStorageInterface::class), new TokenBucket(1, 60))->consume('');
    }

    public function testRefusesACostLargerThanTheBucket(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RateLimiter($this->createStub(LimiterStateStorageInterface::class), new TokenBucket(2, 60))->consume(
            'k',
            3,
        );
    }

    private function brokenStorage(): LimiterStateStorageInterface
    {
        $storage = $this->createStub(LimiterStateStorageInterface::class);
        $storage
            ->method('consume')
            ->willThrowException(new class('Connection refused') extends RuntimeException implements
                StateStorageExceptionInterface {});

        return $storage;
    }
}
