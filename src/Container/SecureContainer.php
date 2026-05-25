<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Container;

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface as PsrContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use ReflectionClass;
use ReflectionException;
use ReflectionMethod;
use Throwable;
use Waffle\Commons\Contracts\Container\ContainerInterface;
use Waffle\Commons\Contracts\Security\Attribute\PublicAccess;
use Waffle\Commons\Contracts\Security\Attribute\Voter;
use Waffle\Commons\Contracts\Security\Exception\SecurityExceptionInterface;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Contracts\Security\VoterInterface;
use Waffle\Commons\Contracts\Service\ResettableInterface;
use Waffle\Commons\Security\Exception\ContainerException;
use Waffle\Commons\Security\Exception\NotFoundException;
use Waffle\Commons\Security\Exception\SecurityException;

/**
 * The SecureContainer acts as a secure decorator around ANY PSR-11 Container.
 * It enforces security rules on retrieved instances.
 *
 * **Beta-1 / SEC-02 — Fail-closed authorization.**
 * `analyze()` rejects any controller action whose target carries no `#[Voter]`
 * rules unless that target (class or method) is explicitly opted-out with
 * `#[PublicAccess]`. The previous "no rules ⇒ allow" semantics were fail-open
 * and have been removed.
 */
final readonly class SecureContainer implements ContainerInterface
{
    /**
     * @param PsrContainerInterface $inner The raw PSR-11 container implementation.
     * @param SecurityInterface $security The security layer.
     */
    public function __construct(
        private PsrContainerInterface $inner,
        private SecurityInterface $security,
        private array $instances = [],
    ) {}

    /**
     * {@inheritdoc}
     */
    #[\Override]
    public function get(string $id): object
    {
        try {
            // 1. Delegate resolution to the inner PSR-11 container
            /** @var object $instance */
            $instance = $this->inner->get($id);

            // 2. Apply security analysis
            $this->security->analyze($instance);

            return $instance;
        } catch (NotFoundExceptionInterface $e) {
            throw new NotFoundException($e->getMessage(), (int) $e->getCode());
        } catch (ContainerExceptionInterface $e) {
            throw new ContainerException($e->getMessage(), (int) $e->getCode());
        } catch (SecurityExceptionInterface $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new ContainerException($e->getMessage(), (int) $e->getCode());
        }
    }

    /**
     * {@inheritdoc}
     */
    #[\Override]
    public function has(string $id): bool
    {
        return $this->inner->has($id);
    }

    /**
     * {@inheritdoc}
     */
    #[\Override]
    public function set(string $id, object|callable|string $concrete): void
    {
        // We attempt to call set() on the inner container if it supports it.
        // Since PSR-11 is read-only, this relies on the inner container having a set() method (like Waffle's).
        if (method_exists($this->inner, 'set')) {
            $this->inner->set($id, $concrete);
        } else {
            throw new ContainerException("The inner container does not support mutable 'set' operations.");
        }
    }

    /**
     * Analyzes security requirements for a given controller action.
     *
     * Fail-closed policy (Beta-1): if neither the controller class nor the
     * target method carries a `#[Voter]`, access is denied with a 403 unless
     * the target is explicitly marked `#[PublicAccess]`.
     *
     * @param string $controller The FQCN of the controller.
     * @param string $method The method name to audit.
     * @throws SecurityException If access is denied or configuration is invalid.
     */
    public function analyze(string $controller, string $method): void
    {
        try {
            $classReflection = new ReflectionClass($controller);
            $methodReflection = $classReflection->getMethod($method);
        } catch (ReflectionException $_) {
            throw new SecurityException(
                message: sprintf('Security Audit failed: Target %s::%s is unreachable.', $controller, $method),
                code: 500,
            );
        }

        // 1. Discover all #[Voter] attributes (security triggers)
        $voters = $this->discoverRules($classReflection, $methodReflection);

        // 2. Fail-closed: no voters means missing policy. Only `#[PublicAccess]`
        //    on the target method or its declaring class opts the action out of
        //    the access check. A method-level voter is enough to satisfy the
        //    requirement even if the class as a whole is unmarked.
        if ($voters === [] && !$this->isPublicAccess($classReflection, $methodReflection)) {
            throw new SecurityException(
                message: sprintf(
                    'Security Policy Violation: %s::%s declares no #[Voter] and is not marked #[PublicAccess]. '
                    . 'Add a Voter or explicitly opt out with #[PublicAccess].',
                    $controller,
                    $method,
                ),
                code: 403,
            );
        }

        // 3. Decision Phase: Every rule must pass (Consensus pattern)
        foreach ($voters as $voterAttribute) {
            $this->vote(voterName: $voterAttribute->name);
        }
    }

    /**
     * Discovers all #[Voter] attributes on the class and the specific method.
     *
     * @return Voter[]
     */
    private function discoverRules(ReflectionClass $class, ReflectionMethod $method): array
    {
        $attributes = [
            ...$class->getAttributes(Voter::class),
            ...$method->getAttributes(Voter::class),
        ];

        return array_map(static fn($attr) => $attr->newInstance(), $attributes);
    }

    /**
     * True when the action is explicitly marked publicly accessible by a
     * `#[PublicAccess]` attribute on either the method or its declaring class.
     */
    private function isPublicAccess(ReflectionClass $class, ReflectionMethod $method): bool
    {
        if ($method->getAttributes(PublicAccess::class) !== []) {
            return true;
        }
        return $class->getAttributes(PublicAccess::class) !== [];
    }

    /**
     * Executes the specific voter/rule logic.
     */
    private function vote(string $voterName): void
    {
        // In Waffle, the 'name' in #[Voter] is expected to be the class name
        // of a concrete Voter implementation.
        if (!class_exists($voterName)) {
            throw new SecurityException(
                message: sprintf('Security configuration error: Voter class "%s" not found.', $voterName),
                code: 500,
            );
        }

        // We instantiate the rule/voter.
        // Note: In Alpha 6, we should fetch this from the Container for Auto-wiring.
        $voterInstance = new $voterName();

        if (!$voterInstance instanceof VoterInterface) {
            throw new SecurityException(
                message: sprintf('Security error: Class "%s" must implement VoterInterface.', $voterName),
                code: 500,
            );
        }

        // The decision is made here.
        if (!$voterInstance->decide()) {
            throw new SecurityException(
                message: sprintf('Security Policy Violation: Access refused by %s.', $voterName),
                code: 403,
            );
        }
    }

    /**
     * Clean all stateful services
     * This method is called by the Kernel at the end of each worker loop
     */
    public function reset(): void
    {
        foreach ($this->instances as $_ => $service) {
            if (!$service instanceof ResettableInterface) {
                continue;
            }

            $service->reset();
        }
    }
}
