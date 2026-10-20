<?php

namespace TouchQue\Resources;

use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Http\HttpClient;

/**
 * TouchQue Actions: your own code at points of the approval pipeline (before
 * the push is sent, the silent sign-in decision, after an approval, fraud
 * reports, device and recovery events). TouchQue runs it in a sandbox; this
 * resource deploys, tests, replays and observes it.
 *
 *     $tq->actions->deploy('night-alert', [
 *         'trigger' => 'approval.decided',
 *         'template' => ['id' => 'alert', 'params' => ['channel' => 'slack', 'when' => ['countries' => ['TR']]]],
 *     ]);
 *
 * Action code itself is JavaScript (`exports.onExecute = async (event, api) => {...}`),
 * whatever language your server is written in. Option keys are the API's
 * (camelCase); an unknown key throws.
 */
class Actions
{
    private const SLUG_RE = '/^[a-z0-9][a-z0-9-]{1,62}$/';
    private const DRAFT_KEYS = ['trigger', 'code', 'template', 'slug', 'secrets', 'allowedHosts', 'capabilities'];
    private const DEPLOY_KEYS = ['trigger', 'code', 'template', 'name', 'secrets', 'allowedHosts', 'capabilities', 'onFailure', 'order', 'enabled', 'activate'];
    private const TEST_KEYS = [...self::DRAFT_KEYS, 'eventId', 'event', 'network'];
    private const DRY_RUN_KEYS = [...self::DRAFT_KEYS, 'replaces', 'onFailure', 'limit', 'since'];
    private const UPDATE_KEYS = ['name', 'enabled', 'order', 'onFailure'];

    private HttpClient $http;
    public ActionSecrets $secrets;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
        $this->secrets = new ActionSecrets($http);
    }

    /**
     * Creates the Action or adds a version and makes it live (idempotent: the
     * same code and settings change nothing). A version asking for a
     * loosening capability (skip_number_match, override_block, allow_silent)
     * waits for an admin's phone approval: the answer then has
     * `deployed => false` and `approval.required`.
     *
     * @param array $options trigger (required for a new Action), code | template, name, secrets,
     *                       allowedHosts, capabilities, onFailure (continue|step_up|deny), order, enabled, activate
     */
    public function deploy(string $slug, array $options): array
    {
        $body = self::pick('deploy', $options, self::DEPLOY_KEYS);
        if (!isset($body['code']) && !isset($body['template'])) {
            throw new TouchQueConfigException('actions->deploy() needs code or template');
        }
        return $this->http->put(self::slugPath($slug), $body);
    }

    public function list(): array
    {
        return $this->http->get('/actions')['actions'] ?? [];
    }

    /** The Action, the active version's code and its versions. */
    public function get(string $slug): array
    {
        return $this->http->get(self::slugPath($slug));
    }

    /** One version, with its code. */
    public function version(string $slug, int $number): array
    {
        return $this->http->get(self::slugPath($slug) . '/versions/' . $number);
    }

    /** Rename, turn on or off, reorder, change onFailure. */
    public function update(string $slug, array $changes): array
    {
        $res = $this->http->patch(self::slugPath($slug), self::pick('update', $changes, self::UPDATE_KEYS));
        return $res['action'] ?? $res;
    }

    public function delete(string $slug): array
    {
        return $this->http->delete(self::slugPath($slug));
    }

    /** Back to `$version`, or to the newest runnable version before the active one. Takes effect at once. */
    public function rollback(string $slug, ?int $version = null): array
    {
        return $this->http->post(self::slugPath($slug) . '/rollback', $version === null ? [] : ['version' => $version]);
    }

    /**
     * Runs a draft (or the deployed Action `slug`) once on a recorded event
     * (`eventId`), your own `event` or the trigger's sample. Sends no notification.
     */
    public function test(array $options): array
    {
        return $this->http->post('/actions/test', self::pick('test', $options, self::TEST_KEYS));
    }

    /**
     * Replays a draft against recent real decisions: how many it would have
     * changed (`changed`, `transitions` such as `['push→number_match' => 12]`),
     * notifications it would have sent, errors and timing. `replaces`: the
     * deployed Action it would replace.
     */
    public function dryRun(array $options): array
    {
        $body = self::pick('dryRun', $options, self::DRY_RUN_KEYS);
        if (isset($body['since']) && $body['since'] instanceof \DateTimeInterface) {
            $body['since'] = $body['since']->format(\DateTimeInterface::ATOM);
        }
        return $this->http->post('/actions/dry-run', $body);
    }

    /** Recorded events (newest first, kept 30 days); use an id with test(). @param array $options trigger, limit */
    public function events(array $options = []): array
    {
        $params = self::pick('events', $options, ['trigger', 'limit']);
        return $this->http->get('/actions/events', $params)['events'] ?? [];
    }

    /** Live runs: decision, notifications, console output, errors. @param array $options limit, before */
    public function logs(string $slug, array $options = []): array
    {
        $params = self::pick('logs', $options, ['limit', 'before']);
        if (isset($params['before']) && $params['before'] instanceof \DateTimeInterface) {
            $params['before'] = $params['before']->format(\DateTimeInterface::ATOM);
        }
        return $this->http->get(self::slugPath($slug) . '/logs', $params)['logs'] ?? [];
    }

    /** `$window`: 1h, 24h (default), 7d or 30d. */
    public function metrics(string $slug, ?string $window = null): array
    {
        return $this->http->get(self::slugPath($slug) . '/metrics', $window === null ? [] : ['window' => $window]);
    }

    /** Every trigger with its decisions, capabilities, notification types and a sample event. */
    public function triggers(): array
    {
        return $this->http->get('/actions/triggers');
    }

    public function templates(): array
    {
        return $this->http->get('/actions/templates')['templates'] ?? [];
    }

    /** A template as plain code (to read, or to start a code Action from). */
    public function renderTemplate(string $id, string $trigger, array $params = []): array
    {
        if (!preg_match('/^[a-z_]{1,64}$/', $id)) {
            throw new TouchQueConfigException('Unknown template id');
        }
        return $this->http->post('/actions/templates/' . $id . '/render', [
            'trigger' => $trigger,
            'params' => $params === [] ? new \stdClass() : $params,
        ]);
    }

    private static function slugPath(string $slug): string
    {
        if (!preg_match(self::SLUG_RE, $slug)) {
            throw new TouchQueConfigException('An Action slug is 2-63 lowercase letters, digits or - (e.g. "night-alert")');
        }
        return '/actions/' . $slug;
    }

    private static function pick(string $method, array $options, array $allowed): array
    {
        $unknown = array_diff(array_keys($options), $allowed);
        if ($unknown) {
            throw new TouchQueConfigException("actions->$method(): unknown option \"" . implode('", "', $unknown) . '"');
        }
        return array_filter($options, static fn ($v) => $v !== null);
    }
}
