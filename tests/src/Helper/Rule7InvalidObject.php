<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper;

class Rule7InvalidObject
{
    public function process(mixed $_untypedArgument): void // Violation
    {
    }
}
