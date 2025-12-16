<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper;

class Rule5ValidObject1
{
    private string $typedPrivate = 'secret';
    public $untypedPublic; // Ignored by Level 5
}
