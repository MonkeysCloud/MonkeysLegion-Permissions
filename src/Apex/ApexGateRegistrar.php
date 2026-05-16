<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Apex;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Decision;
use MonkeysLegion\Permissions\Gate;
use MonkeysLegion\Permissions\Event\ApexPolicyEvaluated;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Registers Apex AI-backed policies as Gate closures so they integrate
 * seamlessly into the Authorizer's evaluation pipeline.
 *
 * Usage:
 *   $registrar = new ApexGateRegistrar($adapter, $gate, $events);
 *   $registrar->register('is-offensive-comment', 'Is this comment offensive or harmful?');
 *   $registrar->register('contains-pii', 'Does this content contain personally identifiable information?');
 *
 *   // Now usable via the standard Authorizer
 *   $authorizer->inspect($user, 'is-offensive-comment', $comment);
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class ApexGateRegistrar
{
    public function __construct(
        private readonly ApexPolicyAdapter $adapter,
        private readonly Gate $gate,
        private readonly ?EventDispatcherInterface $events = null,
    ) {}

    /**
     * Register an AI-backed gate.
     *
     * @param string               $gateName      The gate name (used with $authorizer->inspect()).
     * @param string               $policyPrompt  Natural-language policy question.
     * @param array<string, mixed> $defaultContext Default context passed to every evaluation.
     */
    public function register(
        string $gateName,
        string $policyPrompt,
        array $defaultContext = [],
    ): void {
        $adapter = $this->adapter;
        $events = $this->events;

        $this->gate->define($gateName, function (
            AuthenticatableInterface $identity,
            mixed $resource = null,
        ) use ($adapter, $policyPrompt, $defaultContext, $events): Decision {
            $decision = $adapter->evaluate(
                policyPrompt: $policyPrompt,
                identity: $identity,
                resource: $resource,
                context: $defaultContext,
            );

            $events?->dispatch(new ApexPolicyEvaluated(
                policyPrompt: $policyPrompt,
                userId: (string) $identity->getAuthIdentifier(),
                decision: $decision,
            ));

            // Convert ApexDecision to permissions Decision
            if ($decision->allowed && $decision->confidence >= $adapter->confidenceThreshold()) {
                return Decision::allow("AI: {$decision->reasoning} (confidence: {$decision->confidence})");
            }

            $reason = $decision->isLowConfidence
                ? "AI: Low confidence ({$decision->confidence}) — {$decision->reasoning}"
                : "AI: {$decision->reasoning} (confidence: {$decision->confidence})";

            return Decision::deny($reason);
        });
    }

    /**
     * Register multiple AI gates at once.
     *
     * @param array<string, string> $gates Gate name => policy prompt
     */
    public function registerMany(array $gates): void
    {
        foreach ($gates as $name => $prompt) {
            $this->register($name, $prompt);
        }
    }
}
