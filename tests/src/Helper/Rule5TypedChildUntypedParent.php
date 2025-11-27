<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper;

final class Rule5TypedChildUntypedParent extends Rule5UntypedPrivateParent
{
    private string $typedPrivateChild = 'ok';
}
