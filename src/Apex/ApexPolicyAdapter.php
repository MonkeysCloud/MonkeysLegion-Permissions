<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Apex;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Apex\AI;
use MonkeysLegion\Permissions\Cache\CacheLayer;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Bridges the Apex AI runtime with the permissions system.
 *
 * Sends authorization questions to an LLM with structured prompting,
 * parses the JSON response, and returns an ApexDecision. Results are
 * aggressively memoized to prevent redundant LLM calls.
 *
 * Example policies:
 *   - "Is this comment offensive?"
 *   - "Does this user profile contain personal health information?"
 *   - "Should this transaction be flagged for review?"
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class ApexPolicyAdapter
{
    /** @var array<string, ApexDecision> Per-request memoization. */
    private array $memo = [];

    public function __construct(
        private readonly AI $ai,
        private readonly CacheLayer $cache,
        private readonly string $model = '',
        private readonly float $confidenceThreshold = 0.7,
    ) {}

    /**
     * Evaluate a fuzzy/AI-backed authorization policy.
     *
     * @param string                     $policyPrompt  Natural language policy question.
     * @param AuthenticatableInterface   $identity      The acting user.
     * @param mixed                      $resource      The entity/content being evaluated.
     * @param array<string, mixed>       $context       Additional context for the LLM.
     */
    public function evaluate(
        string $policyPrompt,
        AuthenticatableInterface $identity,
        mixed $resource = null,
        array $context = [],
    ): ApexDecision {
        $cacheKey = $this->buildCacheKey($policyPrompt, $identity, $resource);

        // 1. Check per-request memo
        if (isset($this->memo[$cacheKey])) {
            return $this->memo[$cacheKey];
        }

        // 2. Check persistent cache
        /** @var ApexDecision|null $cached */
        $cached = $this->cache->get("apex_{$cacheKey}", function () use ($policyPrompt, $identity, $resource, $context) {
            return $this->callLlm($policyPrompt, $identity, $resource, $context);
        });

        if ($cached instanceof ApexDecision) {
            $this->memo[$cacheKey] = $cached;
            return $cached;
        }

        // Fallback — should not reach here given CacheLayer always returns a value
        $decision = $this->callLlm($policyPrompt, $identity, $resource, $context);
        $this->memo[$cacheKey] = $decision;
        return $decision;
    }

    /**
     * Evaluate and return true/false based on confidence threshold.
     *
     * Decisions below the confidence threshold are treated as denied
     * to err on the side of caution.
     * @param array<string, mixed> $context
     */
    public function allows(
        string $policyPrompt,
        AuthenticatableInterface $identity,
        mixed $resource = null,
        array $context = [],
    ): bool {
        $decision = $this->evaluate($policyPrompt, $identity, $resource, $context);
        return $decision->allowed && $decision->confidence >= $this->confidenceThreshold;
    }

    /**
     * Invalidate the cache for a specific policy/user/resource combination.
     */
    public function invalidate(
        string $policyPrompt,
        AuthenticatableInterface $identity,
        mixed $resource = null,
    ): void {
        $cacheKey = $this->buildCacheKey($policyPrompt, $identity, $resource);
        unset($this->memo[$cacheKey]);
        $this->cache->invalidate("apex_{$cacheKey}");
    }

    /**
     * Flush all AI policy caches.
     */
    public function flush(): void
    {
        $this->memo = [];
        $this->cache->flush();
    }

    /**
     * Get the confidence threshold.
     */
    public function confidenceThreshold(): float
    {
        return $this->confidenceThreshold;
    }

    // ── Internal ────────────────────────────────────────────────

    /**
     * @param array<string, mixed> $context
     */
    private function callLlm(
        string $policyPrompt,
        AuthenticatableInterface $identity,
        mixed $resource,
        array $context,
    ): ApexDecision {
        $systemPrompt = $this->buildSystemPrompt();
        $userPrompt = $this->buildUserPrompt($policyPrompt, $identity, $resource, $context);

        $options = [];
        if ($this->model !== '') {
            $options['model'] = $this->model;
        }
        $options['response_format'] = ['type' => 'json_object'];
        $options['temperature'] = 0.1; // Low temperature for deterministic decisions

        $response = $this->ai->generate($userPrompt, $systemPrompt, $this->model !== '' ? $this->model : null, $options);

        return $this->parseResponse($response);
    }

    private function buildSystemPrompt(): string
    {
        return <<<'PROMPT'
You are a precise authorization policy evaluator. Your job is to determine whether
an action should be allowed or denied based on the policy description and context provided.

You MUST respond with a valid JSON object containing exactly these fields:
{
  "allowed": true or false,
  "confidence": 0.0 to 1.0 (how confident you are in this decision),
  "reasoning": "Brief explanation of why this decision was made"
}

Rules:
- Be conservative: when in doubt, deny the action (allowed: false)
- Set confidence below 0.5 if the context is ambiguous or insufficient
- Keep reasoning concise but specific
- Never include any text outside the JSON object
PROMPT;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function buildUserPrompt(
        string $policyPrompt,
        AuthenticatableInterface $identity,
        mixed $resource,
        array $context,
    ): string {
        $parts = [];
        $parts[] = "## Policy Question\n{$policyPrompt}";

        // User context
        $userId = $identity->getAuthIdentifier();
        $parts[] = "## Acting User\nUser ID: {$userId}";

        // Resource context
        if ($resource !== null) {
            $resourceDesc = $this->describeResource($resource);
            if ($resourceDesc !== '') {
                $parts[] = "## Resource\n{$resourceDesc}";
            }
        }

        // Additional context
        if ($context !== []) {
            $contextJson = json_encode($context, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            $parts[] = "## Additional Context\n```json\n{$contextJson}\n```";
        }

        $parts[] = "## Instructions\nEvaluate the policy above and respond with JSON only.";

        return implode("\n\n", $parts);
    }

    private function describeResource(mixed $resource): string
    {
        if (is_string($resource)) {
            return "Content: {$resource}";
        }

        if (is_object($resource)) {
            $class = get_class($resource);
            $props = [];

            // Extract public properties via reflection
            try {
                $ref = new \ReflectionClass($resource);
                foreach ($ref->getProperties(\ReflectionProperty::IS_PUBLIC) as $prop) {
                    if ($prop->isInitialized($resource)) {
                        $value = $prop->getValue($resource);
                        if (is_scalar($value) || $value === null) {
                            $props[$prop->getName()] = $value;
                        } elseif ($value instanceof \DateTimeInterface) {
                            $props[$prop->getName()] = $value->format('Y-m-d H:i:s');
                        }
                    }
                }
            } catch (\ReflectionException) {
                // Silently skip if reflection fails
            }

            if ($props !== []) {
                $propsJson = json_encode($props, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
                return "Type: {$class}\nProperties:\n```json\n{$propsJson}\n```";
            }

            return "Type: {$class}";
        }

        return '';
    }

    private function parseResponse(\MonkeysLegion\Apex\DTO\Response $response): ApexDecision
    {
        try {
            /** @var array<string, mixed> $data */
            $data = json_decode($response->content, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            // LLM returned non-JSON — deny by default
            return new ApexDecision(
                allowed: false,
                confidence: 0.0,
                reasoning: "AI response was not valid JSON: {$response->content}",
                model: $response->model,
                tokensUsed: $response->usage->totalTokens,
                latencyMs: $response->latencyMs,
            );
        }

        $allowed = (bool) ($data['allowed'] ?? false);
        $confidenceRaw = $data['confidence'] ?? 0.0;
        $confidence = is_numeric($confidenceRaw) ? (float) $confidenceRaw : 0.0;
        $reasoningRaw = $data['reasoning'] ?? '';
        $reasoning = is_string($reasoningRaw) ? $reasoningRaw : '';

        return new ApexDecision(
            allowed: $allowed,
            confidence: min(1.0, max(0.0, $confidence)),
            reasoning: $reasoning,
            model: $response->model,
            tokensUsed: $response->usage->totalTokens,
            latencyMs: $response->latencyMs,
        );
    }

    private function buildCacheKey(
        string $policyPrompt,
        AuthenticatableInterface $identity,
        mixed $resource,
    ): string {
        $resourceKey = match (true) {
            is_null($resource) => 'null',
            is_string($resource) => md5($resource),
            is_object($resource) => spl_object_hash($resource) . '_' . get_class($resource),
            default => md5(serialize($resource)),
        };

        return md5($policyPrompt . '|' . $identity->getAuthIdentifier() . '|' . $resourceKey);
    }
}
