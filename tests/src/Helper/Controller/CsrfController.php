<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

use Waffle\Commons\Contracts\Security\Csrf\Attribute\RequiresCsrfToken;

/**
 * Fixture controller for CsrfMiddleware tests.
 *
 * Holds one CSRF-protected method and one unprotected method so reflection-based
 * attribute discovery can be exercised both positively and negatively.
 */
final class CsrfController
{
    #[RequiresCsrfToken(id: 'form:test')]
    public function protected(): void {}

    public function unprotected(): void {}
}
