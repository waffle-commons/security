<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper;

final class Rule2ValidObject1
{
    public string $typedProperty = 'hello';
    private $untypedPrivate; // Should be ignored by Level 2
}
