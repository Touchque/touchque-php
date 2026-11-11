<?php

namespace Touchque\Exceptions;

/** `feature_not_in_plan`: the feature is not in the organization's plan. */
class TouchqueFeatureNotInPlanException extends TouchqueFeatureException
{
    protected const REASON = 'not_in_plan';
}
