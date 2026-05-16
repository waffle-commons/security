<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Csrf\Exception;

use Throwable;
use Waffle\Commons\Contracts\Security\Csrf\Exception\InvalidCsrfTokenExceptionInterface;

/**
 * Thrown when the supplied CSRF token fails constant-time comparison
 * against the active token for the route's id.
 */
final class InvalidCsrfTokenException extends CsrfException implements InvalidCsrfTokenExceptionInterface
{
    public function __construct(
        private(set) string $tokenId,
        string $message = '',
        int $code = 403,
        ?Throwable $previous = null,
    ) {
        if ($message === '') {
            $message = sprintf('Invalid CSRF token for id "%s".', $tokenId);
        }
        parent::__construct($message, $code, $previous);
    }

    #[\Override]
    public function getTokenId(): string
    {
        return $this->tokenId;
    }
}
