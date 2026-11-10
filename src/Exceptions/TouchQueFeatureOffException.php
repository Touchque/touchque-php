<?php

namespace TouchQue\Exceptions;

/** `feature_off`: the feature is switched off on this TouchQue deployment. */
class TouchQueFeatureOffException extends TouchQueFeatureException
{
    protected const REASON = 'off';
}
