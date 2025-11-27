<?php

declare(strict_types=1);

namespace Waffle\Commons\Security;

use Waffle\Commons\Contracts\Config\ConfigInterface;
use Waffle\Commons\Security\Abstract\AbstractSecurity;

class Security extends AbstractSecurity
{
    public function __construct(ConfigInterface $cfg)
    {
        $this->level = $cfg->getInt(
            key: 'waffle.security.level',
            default: 1,
        );
    }
}
