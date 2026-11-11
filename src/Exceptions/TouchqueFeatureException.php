<?php

namespace Touchque\Exceptions;

/**
 * The organization behind your workspace cannot use this feature here (HTTP
 * 403). `getFeatureReason()`:
 * - `not_in_plan`: not in its plan (`feature_not_in_plan`); an owner or admin
 *   adds it in the Touchque dashboard;
 * - `read_only`: being turned off (`feature_read_only`); reads still work for
 *   14 days, changes are refused;
 * - `off`: switched off on this Touchque deployment (`feature_off`).
 * `getFeature()` is the catalog id (`device_risk`, `ai_agents`, `mobile_sdk`,
 * `ciam`…). A TouchqueAPIException, so existing `catch` blocks still see it;
 * catch one of the three subclasses to tell them apart.
 */
class TouchqueFeatureException extends TouchqueAPIException
{
    protected const REASON = '';

    private const BY_ERROR = [
        'feature_not_in_plan' => TouchqueFeatureNotInPlanException::class,
        'feature_read_only' => TouchqueFeatureReadOnlyException::class,
        'feature_off' => TouchqueFeatureOffException::class,
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

    /** The exception for an error answer: a feature exception for the three feature codes, else TouchqueAPIException. */
    public static function fromResponse(string $message, int $status, array $data): TouchqueAPIException
    {
        $class = self::BY_ERROR[$data['error'] ?? ''] ?? TouchqueAPIException::class;
        return new $class($message, $status, $data);
    }
}
