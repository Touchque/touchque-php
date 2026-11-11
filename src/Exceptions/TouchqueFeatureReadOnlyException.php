<?php

namespace Touchque\Exceptions;

/** `feature_read_only`: the feature is being turned off; reads work, changes are refused. */
class TouchqueFeatureReadOnlyException extends TouchqueFeatureException
{
    protected const REASON = 'read_only';
}
