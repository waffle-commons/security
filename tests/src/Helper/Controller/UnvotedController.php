<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Controller;

/**
 * Controller without any #[Voter] attribute — analyze() must complete silently.
 */
final class UnvotedController
{
    public function action(): void {}
}
