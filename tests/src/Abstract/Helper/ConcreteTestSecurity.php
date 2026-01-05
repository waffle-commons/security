<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Abstract\Helper;

use Waffle\Commons\Contracts\Config\ConfigInterface;
use Waffle\Commons\Contracts\Config\Exception\InvalidConfigurationExceptionInterface;
use Waffle\Commons\Security\Abstract\AbstractSecurity;

/**
 * A concrete implementation of Security for testing purposes.
 * This allows us to instantiate and test the abstract class's methods.
 */
final class ConcreteTestSecurity extends AbstractSecurity
{
    /**
     * @throws InvalidConfigurationExceptionInterface
     */
    public function __construct(ConfigInterface $config)
    {
        $this->level = $config->getInt(key: 'waffle.security.level', default: 1);
    }
}
