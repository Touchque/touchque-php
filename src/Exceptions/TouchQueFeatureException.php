<?php

namespace TouchQue\Exceptions;

/**
 * The organization behind your workspace cannot use this feature here (HTTP
 * 403). `getFeatureReason()`:
 * - `not_in_plan`: not in its plan (`feature_not_in_plan`); an owner or admin
 *   adds it in the TouchQue dashboard;
 * - `read_only`: being turned off (`feature_read_only`); reads still work for
 *   14 days, changes are refused;
 * - `off`: switched off on this TouchQue deployment (`feature_off`).
 * `getFeature()` is the catalog id (`device_risk`, `ai_agents`, `mobile_sdk`,
 * `ciam`…). A TouchQueAPIException, so existing `catch` blocks still see it;
 * catch one of the three subclasses to tell them apart.
 */
class TouchQueFeatureException extends TouchQueAPIException
{
    protected const REASON = '';

    private const BY_ERROR = [
        'feature_not_in_plan' => TouchQueFeatureNotInPlanException::class,
        'feature_read_only' => TouchQueFeatureReadOnlyException::class,
        'feature_off' => TouchQueFeatureOffException::class,
    ];

    /** The catalog id of the feature (`device_risk`…), or null. */
    public function getFeature(): ?string
    {
        $feature = $this->getData()['feature'] ?? null;
        return is_string($feature) ? $feature : null;
    }

    /** `not_in_plan`, `read_only` or `off`. */
    public function getFeatureReason(): string
    {
        return static::REASON;
    }

    /** The exception for an error answer: a feature exception for the three feature codes, else TouchQueAPIException. */
    public static function fromResponse(string $message, int $status, array $data): TouchQueAPIException
    {
        $class = self::BY_ERROR[$data['error'] ?? ''] ?? TouchQueAPIException::class;
        return new $class($message, $status, $data);
    }
}
