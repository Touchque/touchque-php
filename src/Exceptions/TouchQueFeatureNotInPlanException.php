<?php

namespace TouchQue\Exceptions;

/** `feature_not_in_plan`: the feature is not in the organization's plan. */
class TouchQueFeatureNotInPlanException extends TouchQueFeatureException
{
    protected const REASON = 'not_in_plan';
}
