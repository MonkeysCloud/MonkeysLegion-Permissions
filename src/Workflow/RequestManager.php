<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Workflow;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Database\Contracts\ConnectionManagerInterface;
use MonkeysLegion\Permissions\Entity\PermissionRequest;
use MonkeysLegion\Permissions\Entity\RequestStatus;
use MonkeysLegion\Permissions\Entity\RequestType;
use MonkeysLegion\Permissions\Event\PermissionRequested;
use MonkeysLegion\Permissions\Event\RequestApproved;
use MonkeysLegion\Permissions\Event\RequestDenied;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Orchestrates the permission request-to-grant approval workflow.
 * Handles creation, review (approve/deny), and lifecycle management
 * of PermissionRequest entities, dispatching events at each step.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class RequestManager
{
    public function __construct(
        private readonly ConnectionManagerInterface $db,
        private readonly ?EventDispatcherInterface $events = null,
    ) {}

    // ── Submit Request ─────────────────────────────────────────

    /**
     * Submit a new permission request.
     *
     * @return int The inserted request ID.
     */
    public function requestPermission(
        AuthenticatableInterface $requester,
        string $permission,
        ?string $reason = null,
        int|string|null $tenantId = null,
        ?\DateTimeImmutable $expiresAt = null,
    ): int {
        return $this->createRequest(
            $requester,
            RequestType::Permission,
            $permission,
            $reason,
            $tenantId,
            $expiresAt,
        );
    }

    /**
     * Submit a new role request.
     *
     * @return int The inserted request ID.
     */
    public function requestRole(
        AuthenticatableInterface $requester,
        string $role,
        ?string $reason = null,
        int|string|null $tenantId = null,
        ?\DateTimeImmutable $expiresAt = null,
    ): int {
        return $this->createRequest(
            $requester,
            RequestType::Role,
            $role,
            $reason,
            $tenantId,
            $expiresAt,
        );
    }

    // ── Review Actions ─────────────────────────────────────────

    /**
     * Approve a pending request.
     */
    public function approve(int $requestId, AuthenticatableInterface $reviewer, ?string $note = null): void
    {
        $request = $this->findOrFail($requestId);
        $this->assertPending($request);

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $reviewerId = (string) $reviewer->getAuthIdentifier();

        $this->db->connection()->execute(
            "UPDATE perm_requests 
             SET status = :status, reviewer_id = :reviewer_id, review_note = :note, reviewed_at = :now, updated_at = :now2 
             WHERE id = :id",
            [
                'status'      => RequestStatus::Approved->value,
                'reviewer_id' => $reviewerId,
                'note'        => $note,
                'now'         => $now,
                'now2'        => $now,
                'id'          => $requestId,
            ],
        );

        $reqData = $this->extractRequestData($request);

        $this->events?->dispatch(new RequestApproved(
            requestId: $requestId,
            requesterId: $reqData['requester_id'],
            reviewerId: $reviewerId,
            type: $reqData['type'],
            target: $reqData['target'],
            note: $note,
            tenantId: $reqData['tenant_id'],
        ));
    }

    /**
     * Deny a pending request.
     */
    public function deny(int $requestId, AuthenticatableInterface $reviewer, ?string $note = null): void
    {
        $request = $this->findOrFail($requestId);
        $this->assertPending($request);

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $reviewerId = (string) $reviewer->getAuthIdentifier();

        $this->db->connection()->execute(
            "UPDATE perm_requests 
             SET status = :status, reviewer_id = :reviewer_id, review_note = :note, reviewed_at = :now, updated_at = :now2 
             WHERE id = :id",
            [
                'status'      => RequestStatus::Denied->value,
                'reviewer_id' => $reviewerId,
                'note'        => $note,
                'now'         => $now,
                'now2'        => $now,
                'id'          => $requestId,
            ],
        );

        $reqData = $this->extractRequestData($request);

        $this->events?->dispatch(new RequestDenied(
            requestId: $requestId,
            requesterId: $reqData['requester_id'],
            reviewerId: $reviewerId,
            type: $reqData['type'],
            target: $reqData['target'],
            note: $note,
            tenantId: $reqData['tenant_id'],
        ));
    }

    // ── Queries ─────────────────────────────────────────────────

    /**
     * List pending requests, optionally filtered by tenant.
     *
     * @return list<array<string, mixed>>
     */
    public function listPending(int|string|null $tenantId = null, int $limit = 50, int $offset = 0): array
    {
        $sql = "SELECT * FROM perm_requests WHERE status = :status";
        $params = ['status' => RequestStatus::Pending->value];

        if ($tenantId !== null) {
            $sql .= " AND tenant_id = :tenant_id";
            $params['tenant_id'] = $tenantId;
        }

        $sql .= " ORDER BY created_at ASC LIMIT {$limit} OFFSET {$offset}";

        $stmt = $this->db->connection()->query($sql, $params);
        /** @var list<array<string, mixed>> $rows */
        $rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        return $rows;
    }

    /**
     * List all requests for a specific user.
     *
     * @return list<array<string, mixed>>
     */
    public function listByUser(string $userId, ?RequestStatus $status = null): array
    {
        $sql = "SELECT * FROM perm_requests WHERE requester_id = :user_id";
        $params = ['user_id' => $userId];

        if ($status !== null) {
            $sql .= " AND status = :status";
            $params['status'] = $status->value;
        }

        $sql .= " ORDER BY created_at DESC";

        $stmt = $this->db->connection()->query($sql, $params);
        /** @var list<array<string, mixed>> $rows */
        $rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        return $rows;
    }

    /**
     * Expire all pending requests that have passed their expiration date.
     *
     * @return int Number of expired requests.
     */
    public function expireStale(): int
    {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        return $this->db->connection()->execute(
            "UPDATE perm_requests 
             SET status = :expired, reviewed_at = :now, updated_at = :now2 
             WHERE status = :pending AND expires_at IS NOT NULL AND expires_at < :threshold",
            [
                'expired'   => RequestStatus::Expired->value,
                'now'       => $now,
                'now2'      => $now,
                'pending'   => RequestStatus::Pending->value,
                'threshold' => $now,
            ],
        );
    }

    // ── Internal ────────────────────────────────────────────────

    private function createRequest(
        AuthenticatableInterface $requester,
        RequestType $type,
        string $target,
        ?string $reason,
        int|string|null $tenantId,
        ?\DateTimeImmutable $expiresAt,
    ): int {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $requesterId = (string) $requester->getAuthIdentifier();

        $this->db->connection()->execute(
            "INSERT INTO perm_requests 
             (requester_id, type, target, reason, status, tenant_id, expires_at, created_at, updated_at) 
             VALUES 
             (:requester_id, :type, :target, :reason, :status, :tenant_id, :expires_at, :now, :now2)",
            [
                'requester_id' => $requesterId,
                'type'         => $type->value,
                'target'       => $target,
                'reason'       => $reason,
                'status'       => RequestStatus::Pending->value,
                'tenant_id'    => $tenantId,
                'expires_at'   => $expiresAt?->format('Y-m-d H:i:s'),
                'now'          => $now,
                'now2'         => $now,
            ],
        );

        $lastId = $this->db->connection()->lastInsertId();
        $requestId = (int) ($lastId !== false ? $lastId : 0);

        $this->events?->dispatch(new PermissionRequested(
            requestId: $requestId,
            requesterId: $requesterId,
            type: $type,
            target: $target,
            reason: $reason,
            tenantId: $tenantId,
        ));

        return $requestId;
    }

    /**
     * @return array<string, mixed>
     */
    private function findOrFail(int $requestId): array
    {
        $stmt = $this->db->connection()->query(
            "SELECT * FROM perm_requests WHERE id = :id",
            ['id' => $requestId],
        );

        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        if ($row === false || !is_array($row)) {
            throw new \RuntimeException("Permission request #{$requestId} not found.");
        }

        /** @var array<string, mixed> $row */
        return $row;
    }

    /**
     * @param array<string, mixed> $request
     */
    private function assertPending(array $request): void
    {
        $statusRaw = $request['status'] ?? '';
        $status = is_string($statusRaw) ? $statusRaw : '';

        if ($status !== RequestStatus::Pending->value) {
            $label = RequestStatus::tryFrom($status)?->label() ?? $status;
            throw new \LogicException("Request is already {$label}, cannot modify.");
        }
    }

    /**
     * Extract typed fields from a request row.
     *
     * @param array<string, mixed> $request
     *
     * @return array{requester_id: string, type: RequestType, target: string, tenant_id: int|string|null}
     */
    private function extractRequestData(array $request): array
    {
        $requesterId = isset($request['requester_id']) && is_string($request['requester_id'])
            ? $request['requester_id']
            : '';
        $typeRaw = isset($request['type']) && is_string($request['type'])
            ? $request['type']
            : RequestType::Permission->value;
        $target = isset($request['target']) && is_string($request['target'])
            ? $request['target']
            : '';
        $tenantId = $request['tenant_id'] ?? null;
        $tenantIdTyped = (is_string($tenantId) || is_int($tenantId)) ? $tenantId : null;

        return [
            'requester_id' => $requesterId,
            'type'         => RequestType::from($typeRaw),
            'target'       => $target,
            'tenant_id'    => $tenantIdTyped,
        ];
    }
}
