<?php

namespace TouchQue\Resources;

use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Exceptions\TouchQueRejectedException;
use TouchQue\Exceptions\TouchQueTimeoutException;
use TouchQue\Http\HttpClient;

/**
 * Safe Guard: a Safe transaction approved on the approver's phone for TouchQueSafeGuard (the
 * guard on your Safe). You send the raw transaction; the phone gets the raw fields only, decodes
 * them itself, shows its own rows and signs, with a key only its biometrics unlock, a 105-byte
 * approval of the hash it computed. TouchQue never holds a key that can approve.
 *
 * 1. `request($user, $type, $safeTx)` asks the phone (same pipeline as `login->request`: risk
 *    engine, push limit, Vishing Shield, case code, always biometrics).
 * 2. `waitForApproval($requestId)` (or poll `status`) until the phone answered.
 * 3. Check `safeTx.approval` yourself with `\TouchQue\SafeApproval::verify`: it needs your own
 *    transaction and the approver's key from the guard, not this response, and the purpose you
 *    are about to use it for ('approve' by default; name 'schedule' for a governance change).
 * 4. `purpose` 'approve': `SafeApproval::withApprovals($ownerSignatures, $approvals)` as the
 *    signatures of `execTransaction`. 'schedule': send `SafeApproval::scheduleCall($safe,
 *    $governanceHash, $approvals)` to the guard; the change runs once its waiting time is over.
 */
class SafeGuard
{
    private const NUMBERS = ['value', 'safeTxGas', 'baseGas', 'gasPrice', 'nonce'];
    private const REQUEST_OPTIONS = ['referenceId', 'expiresIn', 'clientIp', 'userAgent'];

    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Asks the approver's phone to approve a Safe transaction.
     *
     *     $sent = $tq->safeGuard->request('treasurer@acme.com', 'safe_payment', [
     *         'chainId' => 1, 'safe' => $safe, 'guard' => $guard,
     *         'tx' => ['to' => $to, 'value' => '0', 'data' => $data, 'operation' => 0, 'nonce' => 42],
     *         'config' => ['threshold' => 2, 'govThreshold' => 3, 'govDelay' => 172800, 'exitDelay' => 259200],
     *         'approverIndex' => 0,
     *     ]);
     *
     * @param string $type an action type from your dashboard
     * @param array $safeTx chainId, safe, guard, tx, config (threshold, govThreshold, govDelay, exitDelay, recipientLock),
     *                      batchTargets, recipients, approverIndex, locale ('en' or 'tr', the default)
     * @param array $options referenceId, expiresIn (seconds, 30 to 300; default 300), clientIp, userAgent
     */
    public function request(string $externalUsername, string $type, array $safeTx, array $options = []): array
    {
        if ($externalUsername === '') {
            throw new TouchQueConfigException('safeGuard->request() needs an externalUsername.');
        }
        if ($type === '') {
            throw new TouchQueConfigException('safeGuard->request() needs a type: an action type from your dashboard.');
        }
        if (!isset($safeTx['tx']) || !is_array($safeTx['tx'])) {
            throw new TouchQueConfigException("safeGuard->request() needs safeTx: ['chainId', 'safe', 'guard', 'tx', 'config', 'approverIndex'].");
        }
        // Large integers go as decimal strings, as the API takes them.
        if (isset($safeTx['chainId']) && is_int($safeTx['chainId'])) {
            $safeTx['chainId'] = (string) $safeTx['chainId'];
        }
        foreach (self::NUMBERS as $name) {
            if (isset($safeTx['tx'][$name]) && is_int($safeTx['tx'][$name])) {
                $safeTx['tx'][$name] = (string) $safeTx['tx'][$name];
            }
        }
        $body = ['externalUsername' => $externalUsername, 'type' => $type, 'safeTx' => $safeTx];
        foreach (self::REQUEST_OPTIONS as $name) {
            if (isset($options[$name]) && $options[$name] !== '') {
                $body[$name] = $options[$name];
            }
        }
        return $this->http->post('/safe-guard/approvals', $body);
    }

    /** The request's status and, once approved, the approval (`safeTx.approval`, 105 bytes hex). */
    public function status(string $requestId): array
    {
        if ($requestId === '') {
            throw new TouchQueConfigException('safeGuard->status() needs a requestId.');
        }
        return $this->http->get('/safe-guard/approvals/' . rawurlencode($requestId));
    }

    /**
     * Polls until the phone approved and returns the status with the approval.
     *
     * @throws TouchQueRejectedException when the person said no.
     * @throws TouchQueTimeoutException when it expired or `$timeoutMs` (default 5 minutes, the request's own life) ran out.
     */
    public function waitForApproval(string $requestId, int $timeoutMs = 300000, int $pollIntervalMs = 1500): array
    {
        $start = microtime(true);
        while (true) {
            $status = $this->status($requestId);
            if (($status['status'] ?? null) === 'CONFIRMED') {
                return $status;
            }
            if (($status['status'] ?? null) === 'REJECTED') {
                throw new TouchQueRejectedException("Request $requestId was rejected by the user.");
            }
            if (($status['status'] ?? null) === 'EXPIRED') {
                throw new TouchQueTimeoutException("Request $requestId expired before it was approved.");
            }
            if ((microtime(true) - $start) * 1000 > $timeoutMs) {
                throw new TouchQueTimeoutException("Safe Guard approval timed out after {$timeoutMs}ms");
            }
            usleep($pollIntervalMs * 1000);
        }
    }
}
