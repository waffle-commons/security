<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

define('APP_ROOT', realpath(path: dirname(path: __DIR__)));
const APP_CONFIG = 'temp_config';

require_once __DIR__ . '/src/AbstractTestCase.php';

// required test helpers, so we include them manually.
require_once __DIR__ . '/src/Helper/Service/AbstractService.php';
require_once __DIR__ . '/src/Helper/Service/NonReadOnlyService.php';
require_once __DIR__ . '/src/Helper/Rule2ValidObject1.php';
require_once __DIR__ . '/src/Helper/Rule2ValidObject2.php';
require_once __DIR__ . '/src/Helper/Rule2InvalidObject.php';
require_once __DIR__ . '/src/Helper/Rule3ValidObject1.php';
require_once __DIR__ . '/src/Helper/Rule3InvalidObject.php';
require_once __DIR__ . '/src/Helper/Rule3ValidObject2.php';
require_once __DIR__ . '/src/Helper/Rule4InvalidObject.php';
require_once __DIR__ . '/src/Helper/Rule4UntypedParent.php';
require_once __DIR__ . '/src/Helper/Rule4TypedChildUntypedParent.php';
require_once __DIR__ . '/src/Helper/Rule4ValidObject.php';
require_once __DIR__ . '/src/Helper/Rule5ValidObject1.php';
require_once __DIR__ . '/src/Helper/Rule5ValidObject2.php';
require_once __DIR__ . '/src/Helper/Rule5InvalidObject.php';
require_once __DIR__ . '/src/Helper/Rule5UntypedPrivateParent.php';
require_once __DIR__ . '/src/Helper/Rule5TypedChildUntypedParent.php';
require_once __DIR__ . '/src/Helper/Rule6ValidObject.php';
require_once __DIR__ . '/src/Helper/Rule7ValidObject.php';
require_once __DIR__ . '/src/Helper/Rule7InvalidObject.php';
require_once __DIR__ . '/src/Helper/Rule7ParentMethod.php';
require_once __DIR__ . '/src/Helper/Rule7ChildMethod.php';
require_once __DIR__ . '/src/Helper/Rule8FinalController.php';
require_once __DIR__ . '/src/Helper/Rule8ViolationName.php';
require_once __DIR__ . '/src/Helper/Rule9ViolationName.php';
require_once __DIR__ . '/src/Helper/Rule10ViolatingObject.php';
require_once __DIR__ . '/src/Abstract/Helper/ConcreteTestSecurity.php';
require_once __DIR__ . '/src/Trait/Helper/FinalReadOnlyClass.php';
require_once __DIR__ . '/src/Trait/Helper/NonFinalTestController.php';
require_once __DIR__ . '/src/Trait/Helper/UninitializedPropertyClass.php';
