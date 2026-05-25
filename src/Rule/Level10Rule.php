<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Rule;

use Waffle\Commons\Contracts\Security\SecurityRuleInterface;
use Waffle\Commons\Security\Exception\SecurityException;
use Waffle\Commons\Utils\Service\ReflectionInspector;

class Level10Rule implements SecurityRuleInterface
{
    public function __construct(
        private readonly ReflectionInspector $inspector = new ReflectionInspector(),
    ) {}

    /**
     * Security Level 10: The strictest set (Full Strictness).
     * [Rule 10]: Ensures all classes are final.
     * @throws SecurityException
     */
    #[\Override]
    public function check(object $object): void
    {
        if (!$this->inspector->isFinal(object: $object)) {
            throw new SecurityException(message: 'Level 10: All classes must be declared final.', code: 500);
        }
    }
}
