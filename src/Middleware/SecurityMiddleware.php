<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Waffle\Commons\Contracts\Constant\Constant;
use Waffle\Commons\Security\Container\SecureContainer;
use Waffle\Commons\Security\Exception\SecurityException;

class SecurityMiddleware implements MiddlewareInterface
{
    public function __construct(
        private(set) readonly SecureContainer $secureContainer,
        private(set) ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * @inheritDoc
     * @throws SecurityException If access is denied by the SecureContainer.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // 1. Extract destination information from Request Attributes
        // We use generic strings to decouple Security from Routing DTOs/Attributes.
        $controller = $request->getAttribute(Constant::ATTR_CLASSNAME);
        $method = $request->getAttribute(Constant::ATTR_METHOD);

        // 2. Fallback check: Some routers might provide the controller as an array [Class, Method]
        if (is_array($controller) && $method === null) {
            $method = $controller[1] ?? null;
            $controller = $controller[0] ?? null;
        }

        if (!is_string($controller) || !is_string($method)) {
            // If no routing information is found, we pass to the next handler (likely a 404).
            // We don't block here to allow the Dispatcher to handle the missing route.
            return $handler->handle($request);
        }

        // 3. Security Analysis (ABAC)
        try {
            // The SecureContainer will read #[Rule] attributes on the class and method.
            $this->secureContainer->analyze($controller, $method);
        } catch (SecurityException $e) {
            // 4. Defense: Trace the denied access attempt
            $this->logDenial($request, $e, $controller, $method);

            // Rethrow the exception. The ErrorHandlerMiddleware will take care
            // of rendering the standardized 403 JSON response.
            throw $e;
        }

        // 5. Authorization granted: Continue the pipeline
        return $handler->handle($request);
    }

    /**
     * Logs the details of the access denial for security auditing.
     */
    private function logDenial(
        ServerRequestInterface $request,
        SecurityException $e,
        string $controller,
        string $method,
    ): void {
        $this->logger->warning('[sec] Access denied: ' . $e->getMessage(), [
            'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown',
            'uri' => (string) $request->getUri(),
            'target' => sprintf('%s::%s', $controller, $method),
            'reason' => $e->getMessage(),
        ]);
    }
}
