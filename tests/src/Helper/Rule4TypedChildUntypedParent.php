<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper;

final class Rule4TypedChildUntypedParent extends Rule4UntypedParent
{
    public function typedChildMethod(): string
    {
        return 'ok';
    }
}
