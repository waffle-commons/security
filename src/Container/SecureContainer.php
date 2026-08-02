<?php

declare(strict_types=1);

namespace Waffle\Commons\Security\Container;

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface as PsrContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use ReflectionException;
use ReflectionMethod;
use Throwable;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Container\ContainerInterface;
use Waffle\Commons\Contracts\Security\Attribute\PublicAccess;
use Waffle\Commons\Contracts\Security\Attribute\Voter;
use Waffle\Commons\Contracts\Security\Exception\SecurityExceptionInterface;
use Waffle\Commons\Contracts\Security\SecurityInterface;
use Waffle\Commons\Contracts\Security\SubjectResolverInterface;
use Waffle\Commons\Contracts\Security\VoterInterface;
use Waffle\Commons\Contracts\Service\ResettableInterface;
use Waffle\Commons\Contracts\Telemetry\Enum\SpanKind;
use Waffle\Commons\Contracts\Telemetry\Enum\SpanStatus;
use Waffle\Commons\Contracts\Telemetry\NullTracer;
use Waffle\Commons\Contracts\Telemetry\TracerInterface;
use Waffle\Commons\Security\Exception\ContainerException;
use Waffle\Commons\Security\Exception\NotFoundException;
use Waffle\Commons\Security\Exception\SecurityException;

/**
 * The SecureContainer acts as a secure decorator around ANY PSR-11 Container.
 * It enforces security rules on retrieved instances.
 *
 * **Two distinct, documented layers (ARCH-01).**
 * 1. Object integrity — `get()` runs the configured Level1…Level10 ladder
 *    (`SecurityInterface::analyze()`, strictness driven by `waffle.security.level`)
 *    over every service it resolves: a structural/consistency check, NOT access
 *    control.
 * 2. Route authorization — `analyze(controller, method)` runs the `#[Voter]`
 *    consensus (context-aware, AUTHZ-01) for the dispatched action. This is the
 *    single access-control entry point; there is no `#[Rule]` attribute path.
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
     * @param SecurityContextInterface $securityContext Request-scoped authenticated identity, threaded into voters.
     * @param SubjectResolverInterface|null $subjectResolver SEC-05: optional hook that hydrates the domain
     *        subject (e.g. the entity an `{id}` route parameter identifies) so voters can express
     *        object-level (IDOR) rules. Resolution is LAZY and voter-gated: it runs only once the
     *        dispatched action is known to carry at least one #[Voter] — #[PublicAccess] actions with
     *        no voters never invoke it (no hydration cost, no false 403 from a failed lookup). A
     *        resolver throw on a voted route is fail-closed (403). Null keeps request-shaped voting.
     */
    public function __construct(
        private PsrContainerInterface $inner,
        private SecurityInterface $security,
        private SecurityContextInterface $securityContext,
        private array $instances = [],
        private TracerInterface $tracer = new NullTracer(),
        private ?SubjectResolverInterface $subjectResolver = null,
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
     * the target method is explicitly marked `#[PublicAccess]`.
     *
     * @param string $controller The FQCN of the controller.
     * @param string $method The method name to audit.
     * @param ServerRequestInterface|null $request Current request, threaded to voters as the decision subject
     *        whenever no richer $resolvedSubject is supplied.
     * @param mixed $resolvedSubject SEC-05: the real domain entity/model under decision (e.g. the `Order`
     *        a route's `{id}` identifies), when a caller has already resolved one — takes precedence over
     *        both the ctor-injected {@see SubjectResolverInterface} and $request, so voters can express
     *        true object-level (IDOR) rules instead of only request-shaped ones. When no explicit subject
     *        is supplied, the ctor-injected resolver (if any) is consulted LAZILY, only after voter
     *        discovery finds at least one #[Voter] — public, unvoted actions never trigger resolution.
     *        A resolver failure on a voted route is fail-closed: it becomes a 403 SecurityException
     *        (previous chained) that flows through the middleware's standard denial-logging path.
     * @throws SecurityException If access is denied or configuration is invalid.
     */
    public function analyze(
        string $controller,
        string $method,
        ?ServerRequestInterface $request = null,
        mixed $resolvedSubject = null,
    ): void {
        $span = $this->tracer->startSpan('waffle.security.authorize', SpanKind::Internal);
        $span->setAttribute('code.namespace', $controller);
        $span->setAttribute('code.function', $method);

        try {
            $this->authorize($controller, $method, $request, $resolvedSubject);
        } catch (SecurityException $denied) {
            $span->recordException($denied);
            $span->setStatus(SpanStatus::Error);

            throw $denied;
        } finally {
            $span->end();
        }
    }

    /**
     * Runs the fail-closed #[Voter] consensus for a controller action.
     *
     * @throws SecurityException If access is denied or the target is unreachable.
     */
    private function authorize(
        string $controller,
        string $method,
        ?ServerRequestInterface $request,
        mixed $resolvedSubject,
    ): void {
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
        //    on the target method itself opts the action out of the access check
        //    (SEC-05: method-only — a class-level opt-out would silently expose
        //    any future unvoted method added to that controller).
        if ($voters === []) {
            if (!$this->isPublicAccess($methodReflection)) {
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

            // #[PublicAccess] with zero voters: no decision will consume a
            // subject, so the subject resolver is deliberately NEVER consulted
            // — a failed lookup (stale link, unknown id) must not turn a
            // public action into a 403, and public routes must not pay the
            // hydration cost of a discarded subject (SEC-05).
            return;
        }

        // 3. Decision Phase: every voter must pass (Consensus pattern). The
        //    decision subject, in precedence order: the caller-supplied
        //    $resolvedSubject, then the ctor-injected resolver's result
        //    (computed lazily, only now that voters exist to consume it),
        //    then the bare request — so voters can express true object-level
        //    (IDOR) rules whenever a richer subject is available (SEC-05).
        $subject = $resolvedSubject ?? $this->resolveSubject($request) ?? $request;
        foreach ($voters as $voterAttribute) {
            $this->vote(voterName: $voterAttribute->name, subject: $subject);
        }
    }

    /**
     * Lazily resolves the domain subject via the ctor-injected resolver (SEC-05).
     *
     * Called only when the dispatched action carries at least one #[Voter] —
     * public, unvoted actions never trigger resolution. Fail-closed: any
     * resolver throw becomes a 403 SecurityException (previous chained), which
     * bubbles out of analyze() and through the middleware's standard
     * denial-logging path, exactly like a voter denial.
     *
     * @return mixed The resolved domain subject, or null when no resolver is
     *         wired, no request is available, or the route carries no resource.
     * @throws SecurityException When the resolver fails (fail-closed).
     */
    private function resolveSubject(?ServerRequestInterface $request): mixed
    {
        if ($this->subjectResolver === null || $request === null) {
            return null;
        }

        try {
            return $this->subjectResolver->resolve($request);
        } catch (Throwable $failure) {
            throw new SecurityException(
                message: sprintf(
                    'Security subject resolution failed — denying access (fail-closed): %s',
                    $failure->getMessage(),
                ),
                code: 403,
                previous: $failure,
            );
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
     * `#[PublicAccess]` attribute on the method itself (SEC-05: method-only —
     * see {@see PublicAccess} for why class-level placement was removed).
     */
    private function isPublicAccess(ReflectionMethod $method): bool
    {
        return $method->getAttributes(PublicAccess::class) !== [];
    }

    /**
     * Resolves and runs a single voter (Consensus pattern).
     *
     * AUTHZ-01: the voter is resolved THROUGH the inner PSR-11 container so it is
     * autowired with its declared collaborators, instead of a context-free
     * `new $voterName()`. The authenticated identity reaches the voter via
     * $this->securityContext; $subject carries the decision target (a resolved
     * domain entity when one is available — explicit or via the ctor-injected
     * subject resolver — otherwise the current request).
     *
     * @param mixed $subject The resource under decision (or the PSR-7 request).
     */
    private function vote(string $voterName, mixed $subject = null): void
    {
        // In Waffle, the 'name' in #[Voter] is expected to be the class name
        // of a concrete Voter implementation.
        if (!class_exists($voterName)) {
            throw new SecurityException(
                message: sprintf('Security configuration error: Voter class "%s" not found.', $voterName),
                code: 500,
            );
        }

        try {
            // The inner Waffle container autowires any instantiable class-string
            // on get(), so ownership / IDOR voters receive their dependencies.
            /** @var object $voterInstance */
            $voterInstance = $this->inner->get($voterName);
        } catch (ContainerExceptionInterface $e) {
            throw new SecurityException(
                message: sprintf(
                    'Security configuration error: Voter "%s" could not be resolved (%s).',
                    $voterName,
                    $e->getMessage(),
                ),
                code: 500,
            );
        }

        if (!$voterInstance instanceof VoterInterface) {
            throw new SecurityException(
                message: sprintf('Security error: Class "%s" must implement VoterInterface.', $voterName),
                code: 500,
            );
        }

        // The decision is made here, with the authenticated context + subject.
        if (!$voterInstance->decide($this->securityContext, $subject)) {
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
        // Decorator discipline: forward the reset to the wrapped container
        // FIRST so its registered resettable services (auth SecurityContext,
        // connection pools, …) are wiped every worker loop. Without this
        // forwarding the kernel's reset chain would stop at the decorator and
        // request-scoped state would leak across requests (RFC-021 §4.1).
        if ($this->inner instanceof ResettableInterface) {
            $this->inner->reset();
        }

        foreach ($this->instances as $_ => $service) {
            if (!$service instanceof ResettableInterface) {
                continue;
            }

            $service->reset();
        }
    }
}
