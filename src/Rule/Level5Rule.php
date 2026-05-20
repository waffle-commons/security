<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Rule;

use ReflectionProperty;
use Waffle\Commons\Contracts\Security\SecurityRuleInterface;
use Waffle\Commons\Security\Exception\SecurityException;
use Waffle\Commons\Utils\Service\ReflectionInspector;

class Level5Rule implements SecurityRuleInterface
{
    public function __construct(
        private readonly ReflectionInspector $inspector = new ReflectionInspector(),
    ) {}

    /**
     * Security Level 5: Ensures good encapsulation.
     * [Rule 5]: For example, ensures *private* properties are typed.
     * @throws SecurityException
     */
    #[\Override]
    public function check(object $object): void
    {
        $properties = $this->inspector->getProperties(object: $object, filter: ReflectionProperty::IS_PRIVATE);
        $class = get_class($object);

        foreach ($properties as $property) {
            if (!($property->getType() === null && $property->getDeclaringClass()->getName() === $class)) {
                continue;
            }

            throw new SecurityException(
                message: "Level 5: Private property '{$property->getName()}' in {$class} must be typed.",
                code: 500,
            );
        }
    }
}
