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
use Waffle\Commons\Contracts\Telemetry\Metrics\MetricsRegistryInterface;

/**
 * A configured token-bucket limiter ([NET-01], RFC-017 §3.1): one bucket, one shared storage, one
 * failure mode. Its state lives in the storage, never in worker memory. Stateless.
 *
 * A storage outage applies the failure mode with a warning log and a metric (`on_storage_failure`,
 * RFC-017 §4), labelled by mode only: a key would be unbounded cardinality.
 */
final readonly class RateLimiter implements RateLimiterInterface
{
    public const string STORAGE_ERRORS_METRIC = 'waffle_ratelimit_storage_errors_total';

    public function __construct(
        private LimiterStateStorageInterface $storage,
        private TokenBucket $bucket,
        private StorageFailureMode $onStorageFailure = StorageFailureMode::Open,
        private LoggerInterface $logger = new NullLogger(),
        private ?MetricsRegistryInterface $metrics = null,
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
            $this->metrics?->increment(self::STORAGE_ERRORS_METRIC, 1.0, ['mode' => $this->onStorageFailure->value]);
            $this->logger->warning('Rate-limit storage unavailable; on_storage_failure is {mode}.', [
                'mode' => $this->onStorageFailure->value,
                'exception' => $e,
            ]);

            $capacity = $this->bucket->capacity;

            return $this->onStorageFailure === StorageFailureMode::Open
                ? new RateLimitDecision(true, $capacity, $capacity, 0, 0, false)
                : new RateLimitDecision(false, $capacity, 0, 0, 1, false);
        }
    }
}
