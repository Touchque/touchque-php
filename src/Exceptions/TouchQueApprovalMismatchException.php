<?php

namespace TouchQue\Exceptions;

/**
 * An approval token does not say what you are about to execute (another
 * person, action type, amount, recipient...), or it is not a valid token
 * from TouchQue. Do not execute.
 */
class TouchQueApprovalMismatchException extends TouchQueException
{
}
