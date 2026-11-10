<?php

namespace TouchQue\Exceptions;

/** `feature_read_only`: the feature is being turned off; reads work, changes are refused. */
class TouchQueFeatureReadOnlyException extends TouchQueFeatureException
{
    protected const REASON = 'read_only';
}
