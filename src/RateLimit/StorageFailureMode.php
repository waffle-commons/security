<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\RateLimit;

/**
 * What a limiter does when its shared storage is unavailable (`on_storage_failure`, RFC-017 §4).
 *
 * `Open` lets the call through, logged and without `RateLimit-*` headers: the limiter protects capacity,
 * and a Redis outage must not take the whole API down. `Closed` refuses it with a 503: recommended where
 * the limiter is the brute-force defence (authentication endpoints).
 */
enum StorageFailureMode: string
{
    case Open = 'open';
    case Closed = 'closed';
}
