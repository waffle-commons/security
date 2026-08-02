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
    /**
     * @param SecureContainer $secureContainer Runs the #[Voter] consensus for the dispatched action.
     *        SEC-05: subject resolution (hydrating the entity an `{id}` route parameter identifies)
     *        lives INSIDE the SecureContainer — ctor-injected there, resolved lazily and only for
     *        voted actions — so this middleware stays a thin trigger + denial-audit layer.
     * @param LoggerInterface|null $logger SECURITY-channel logger for denial audit trails.
     */
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

            // Write the normalised target back so every downstream consumer —
            // subject resolvers reading the request inside the SecureContainer,
            // later middlewares, the dispatcher — sees one canonical string
            // shape even when the router provided the array form.
            if (is_string($controller) && is_string($method)) {
                $request = $request->withAttribute(Constant::ATTR_CLASSNAME, $controller)->withAttribute(
                    Constant::ATTR_METHOD,
                    $method,
                );
            }
        }

        if (!is_string($controller) || !is_string($method)) {
            // If no routing information is found, we pass to the next handler (likely a 404).
            // We don't block here to allow the Dispatcher to handle the missing route.
            return $handler->handle($request);
        }

        // 3. Security Analysis (ABAC)
        try {
            // The SecureContainer reads #[Voter] attributes on the class and
            // method and runs each voter with the authenticated context. SEC-05:
            // it also owns subject resolution — lazy, voter-gated, fail-closed —
            // so a resolver failure surfaces here as a SecurityException and is
            // logged below exactly like any voter denial.
            $this->secureContainer->analyze($controller, $method, $request);
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
