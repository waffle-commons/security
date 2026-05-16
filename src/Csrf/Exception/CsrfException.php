<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Csrf\Exception;

use Exception;
use Throwable;
use Waffle\Commons\Contracts\Security\Csrf\Exception\CsrfExceptionInterface;

/**
 * Base CSRF failure.
 *
 * Implements `CsrfExceptionInterface`, which extends `SecurityExceptionInterface`,
 * so the existing error-handler routing (HTTP 403 in `JsonErrorRenderer`) covers
 * CSRF denials with no extra plumbing. Cannot extend the concrete `SecurityException`
 * because that class is `final`; the shared marker is the interface contract.
 */
class CsrfException extends Exception implements CsrfExceptionInterface
{
    public function __construct(
        string $message = 'CSRF validation failed.',
        int $code = 403,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * {@inheritdoc}
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function serialize(): array
    {
        return [
            'message' => $this->getMessage(),
            'code' => $this->getCode(),
        ];
    }
}
