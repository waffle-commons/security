<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper;

class Rule7ValidObject
{
    public function activate(string $_name, int $_id): void {}

    public function deactivate(string $_name, int $_id): void {}

    public function usesMixedWithDefault(mixed $_data = null): void {} // Allowed if default is present

    protected function protectedMethod($_untyped): void {} // Ignored
}
