<?php

namespace Touchque\Exceptions;

/**
 * An approval token does not say what you are about to execute (another
 * person, action type, amount, recipient...), or it is not a valid token
 * from Touchque. Do not execute.
 */
class TouchqueApprovalMismatchException extends TouchqueException
{
}
