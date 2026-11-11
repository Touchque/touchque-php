<?php

namespace Touchque\Exceptions;

/**
 * An AI agent's approval ended without a usable approval: getStatus() is
 * rejected, blocked, revoked, expired, stale (approved too long ago) or
 * redeemed (already used).
 */
class TouchqueApprovalException extends TouchqueException
{
    private string $approvalId;
    private string $status;
    private ?string $reason;

    public function __construct(string $approvalId, string $status, ?string $reason = null)
    {
        parent::__construct("Touchque: approval '{$approvalId}' is {$status}" . ($reason ? " ({$reason})" : ''));
        $this->approvalId = $approvalId;
        $this->status = $status;
        $this->reason = $reason;
    }

    public function getApprovalId(): string
    {
        return $this->approvalId;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }
}
