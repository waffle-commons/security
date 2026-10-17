<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\RateLimit;

use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Waffle\Commons\Contracts\RateLimit\Exception\StateStorageExceptionInterface;
use Waffle\Commons\Contracts\RateLimit\LimiterStateStorageInterface;
use Waffle\Commons\Contracts\RateLimit\RateLimitDecision;
use Waffle\Commons\Contracts\RateLimit\RateLimiterInterface;
use Waffle\Commons\Contracts\RateLimit\TokenBucket;

/**
 * A configured token-bucket limiter ([NET-01], RFC-017 §3.1): one bucket, one shared storage, one
 * failure mode. Its state lives in the storage, never in worker memory. Stateless.
 */
final readonly class RateLimiter implements RateLimiterInterface
{
    public function __construct(
        private LimiterStateStorageInterface $storage,
        private TokenBucket $bucket,
        private StorageFailureMode $onStorageFailure = StorageFailureMode::Open,
        private LoggerInterface $logger = new NullLogger(),
    ) {}

    /**
     * @throws InvalidArgumentException When the key is empty or the cost does not fit the bucket.
     */
    #[\Override]
    public function consume(string $key, int $cost = 1): RateLimitDecision
    {
        if ($key === '') {
            throw new InvalidArgumentException('A rate-limit key must not be empty.');
        }
        if ($cost < 1 || $cost > $this->bucket->capacity) {
            throw new InvalidArgumentException('A rate-limit cost must be between 1 and the bucket capacity.');
        }

        try {
            return $this->storage->consume($key, $this->bucket, $cost);
        } catch (StateStorageExceptionInterface $e) {
            $this->logger->warning('Rate-limit storage unavailable; the call is let through: {open}.', [
                'open' => $this->onStorageFailure === StorageFailureMode::Open ? 'yes' : 'no',
                'exception' => $e,
            ]);

            $capacity = $this->bucket->capacity;

            return $this->onStorageFailure === StorageFailureMode::Open
                ? new RateLimitDecision(true, $capacity, $capacity, 0, 0, false)
                : new RateLimitDecision(false, $capacity, 0, 0, 1, false);
        }
    }
}
