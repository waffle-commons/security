<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Exception;

use Psr\Container\ContainerExceptionInterface;
use RuntimeException;

class ContainerException extends RuntimeException implements ContainerExceptionInterface {}
