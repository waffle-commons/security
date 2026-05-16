<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Csrf\Exception;

use Throwable;
use Waffle\Commons\Contracts\Security\Csrf\Exception\MissingCsrfTokenExceptionInterface;

/**
 * Thrown when a route marked `#[RequiresCsrfToken]` is invoked with no token supplied
 * in any expected location (header, form field, cookie).
 */
final class MissingCsrfTokenException extends CsrfException implements MissingCsrfTokenExceptionInterface
{
    public function __construct(
        private(set) string $tokenId,
        string $message = '',
        int $code = 403,
        ?Throwable $previous = null,
    ) {
        if ($message === '') {
            $message = sprintf('Missing CSRF token for id "%s".', $tokenId);
        }
        parent::__construct($message, $code, $previous);
    }

    #[\Override]
    public function getTokenId(): string
    {
        return $this->tokenId;
    }
}
