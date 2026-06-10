<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Cors;

use InvalidArgumentException;

/**
 * Immutable CORS policy (SEC-04) — fail-closed by default.
 *
 * An empty {@see self::$allowedOrigins} means NO cross-origin request is ever
 * accepted. Origins are matched **exactly** (`scheme://host[:port]`); a
 * wildcard `*` is permitted only for non-credentialed policies — combining `*`
 * with credentials is rejected at construction time, per the Fetch standard,
 * because it would expose authenticated responses to every site.
 */
final readonly class CorsPolicy
{
    /**
     * @param list<string> $allowedOrigins Exact origins; `*` only without credentials.
     * @param list<string> $allowedMethods Methods advertised on pre-flight.
     * @param list<string> $allowedHeaders Request headers advertised on pre-flight.
     */
    public function __construct(
        public array $allowedOrigins = [],
        public array $allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        public array $allowedHeaders = ['Content-Type', 'Authorization', 'X-CSRF-Token'],
        public bool $allowCredentials = false,
        public int $maxAge = 600,
    ) {
        if ($allowCredentials && in_array('*', $allowedOrigins, true)) {
            throw new InvalidArgumentException('A wildcard "*" origin must not be combined with credentialed CORS.');
        }
    }

    /**
     * True when `$origin` is explicitly allow-listed, or the policy is an
     * uncredentialed wildcard. An empty allow-list always returns false
     * (fail-closed).
     */
    public function allowsOrigin(string $origin): bool
    {
        if ($origin === '') {
            return false;
        }

        if (in_array($origin, $this->allowedOrigins, true)) {
            return true;
        }

        return !$this->allowCredentials && in_array('*', $this->allowedOrigins, true);
    }
}
