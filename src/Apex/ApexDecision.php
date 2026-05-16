<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Apex;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Value object for an AI policy evaluation result.
 *
 * Contains the boolean decision, confidence score, reasoning from the LLM,
 * and token usage metadata for cost tracking.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class ApexDecision
{
    public function __construct(
        public readonly bool $allowed,
        public readonly float $confidence,
        public readonly string $reasoning,
        public readonly string $model,
        public readonly int $tokensUsed = 0,
        public readonly float $latencyMs = 0.0,
        public readonly bool $fromCache = false,
    ) {}

    // ── Computed Properties ─────────────────────────────────────

    public bool $isHighConfidence {
        get => $this->confidence >= 0.8;
    }

    public bool $isLowConfidence {
        get => $this->confidence < 0.5;
    }

    /**
     * Serialize for cache persistence.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'allowed'    => $this->allowed,
            'confidence' => $this->confidence,
            'reasoning'  => $this->reasoning,
            'model'      => $this->model,
            'tokensUsed' => $this->tokensUsed,
            'latencyMs'  => $this->latencyMs,
            'fromCache'  => $this->fromCache,
        ];
    }

    /**
     * Reconstruct from cached array.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $confRaw = $data['confidence'] ?? 0.0;
        $confidence = is_float($confRaw) ? $confRaw : (is_numeric($confRaw) ? floatval($confRaw) : 0.0);
        $latRaw = $data['latencyMs'] ?? 0.0;
        $latency = is_float($latRaw) ? $latRaw : (is_numeric($latRaw) ? floatval($latRaw) : 0.0);

        return new self(
            allowed: (bool) ($data['allowed'] ?? false),
            confidence: $confidence,
            reasoning: is_string($data['reasoning'] ?? null) ? $data['reasoning'] : '',
            model: is_string($data['model'] ?? null) ? $data['model'] : '',
            tokensUsed: is_int($data['tokensUsed'] ?? null) ? $data['tokensUsed'] : 0,
            latencyMs: $latency,
            fromCache: true,
        );
    }
}
