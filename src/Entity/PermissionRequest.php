<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Entity;

use MonkeysLegion\Entity\Attributes\Entity;
use MonkeysLegion\Entity\Attributes\Id;
use MonkeysLegion\Entity\Attributes\Field;
use MonkeysLegion\Entity\Attributes\Timestamps;
use MonkeysLegion\Entity\Attributes\Fillable;
use MonkeysLegion\Entity\Attributes\Index;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Represents a user's request to be granted a permission or role.
 * Part of the request-to-grant approval workflow (v1.2).
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
#[Entity(table: 'perm_requests')]
#[Timestamps]
#[Index(columns: ['requester_id', 'status'], name: 'idx_perm_req_user_status')]
#[Index(columns: ['status'], name: 'idx_perm_req_status')]
#[Index(columns: ['tenant_id'], name: 'idx_perm_req_tenant')]
final class PermissionRequest
{
    // ── Fields ──────────────────────────────────────────────────

    #[Id]
    #[Field(type: 'integer')]
    public private(set) int $id;

    #[Field(type: 'string', length: 36)]
    #[Fillable]
    public string $requester_id;

    #[Field(type: 'string', length: 16)]
    #[Fillable]
    public string $type {
        set(string $value) {
            // Validate against backed enum
            RequestType::from($value);
            $this->type = $value;
        }
    }

    #[Field(type: 'string', length: 128)]
    #[Fillable]
    public string $target {
        set(string $value) {
            if (trim($value) === '') {
                throw new \InvalidArgumentException('Request target cannot be empty.');
            }
            $this->target = trim($value);
        }
    }

    #[Field(type: 'text', nullable: true)]
    #[Fillable]
    public ?string $reason = null;

    #[Field(type: 'string', length: 16)]
    public string $status {
        set(string $value) {
            RequestStatus::from($value);
            $this->status = $value;
        }
    }

    #[Field(type: 'string', length: 36, nullable: true)]
    public ?string $reviewer_id = null;

    #[Field(type: 'text', nullable: true)]
    public ?string $review_note = null;

    #[Field(type: 'datetime', nullable: true)]
    public ?\DateTimeImmutable $reviewed_at = null;

    #[Field(type: 'datetime', nullable: true)]
    #[Fillable]
    public ?\DateTimeImmutable $expires_at = null;

    #[Field(type: 'string', length: 36, nullable: true)]
    #[Fillable]
    public ?string $tenant_id = null;

    // ── Computed Properties ─────────────────────────────────────

    public RequestStatus $statusEnum {
        get => RequestStatus::from($this->status);
    }

    public RequestType $typeEnum {
        get => RequestType::from($this->type);
    }

    public bool $isPending {
        get => $this->statusEnum === RequestStatus::Pending;
    }

    public bool $isResolved {
        get => $this->statusEnum->isFinal();
    }

    public bool $isExpired {
        get => $this->expires_at !== null && $this->expires_at < new \DateTimeImmutable();
    }

    // ── Factory ─────────────────────────────────────────────────

    public static function createPermissionRequest(
        string $requesterId,
        string $permission,
        ?string $reason = null,
        ?string $tenantId = null,
        ?\DateTimeImmutable $expiresAt = null,
    ): self {
        $request = new self();
        $request->requester_id = $requesterId;
        $request->type = RequestType::Permission->value;
        $request->target = $permission;
        $request->reason = $reason;
        $request->status = RequestStatus::Pending->value;
        $request->tenant_id = $tenantId;
        $request->expires_at = $expiresAt;
        return $request;
    }

    public static function createRoleRequest(
        string $requesterId,
        string $role,
        ?string $reason = null,
        ?string $tenantId = null,
        ?\DateTimeImmutable $expiresAt = null,
    ): self {
        $request = new self();
        $request->requester_id = $requesterId;
        $request->type = RequestType::Role->value;
        $request->target = $role;
        $request->reason = $reason;
        $request->status = RequestStatus::Pending->value;
        $request->tenant_id = $tenantId;
        $request->expires_at = $expiresAt;
        return $request;
    }

    // ── Actions ─────────────────────────────────────────────────

    public function approve(string $reviewerId, ?string $note = null): void
    {
        $this->assertPending();
        $this->status = RequestStatus::Approved->value;
        $this->reviewer_id = $reviewerId;
        $this->review_note = $note;
        $this->reviewed_at = new \DateTimeImmutable();
    }

    public function deny(string $reviewerId, ?string $note = null): void
    {
        $this->assertPending();
        $this->status = RequestStatus::Denied->value;
        $this->reviewer_id = $reviewerId;
        $this->review_note = $note;
        $this->reviewed_at = new \DateTimeImmutable();
    }

    public function revoke(string $reviewerId, ?string $note = null): void
    {
        if ($this->statusEnum !== RequestStatus::Approved) {
            throw new \LogicException('Only approved requests can be revoked.');
        }
        $this->status = RequestStatus::Revoked->value;
        $this->reviewer_id = $reviewerId;
        $this->review_note = $note;
        $this->reviewed_at = new \DateTimeImmutable();
    }

    public function markExpired(): void
    {
        $this->assertPending();
        $this->status = RequestStatus::Expired->value;
        $this->reviewed_at = new \DateTimeImmutable();
    }

    private function assertPending(): void
    {
        if ($this->statusEnum !== RequestStatus::Pending) {
            throw new \LogicException("Request is already {$this->statusEnum->label()}, cannot modify.");
        }
    }
}
