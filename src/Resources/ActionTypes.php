<?php

namespace Touchque\Resources;

use Touchque\Http\HttpClient;

/** Action types ("LOGIN", "SEND_MONEY", …) — what a user is asked to
 * approve. Define them from code at start-up instead of clicking them into
 * the Dashboard. (Before 4.0 this was `$tq->actions`; `$tq->actions` is
 * Touchque Actions now.) */
class ActionTypes
{
    /** The Second Thought questions an action type can ask (at most two). */
    public const SECOND_THOUGHT_QUESTIONS = [
        'someone_guiding',
        'safe_account',
        'remote_access',
        'asked_for_code',
        'support_call',
        'met_online',
        'promised_return',
        'know_recipient',
        'sim_in_hand',
    ];

    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    /**
     * Creates the action type, or updates its name, description, critical flag
     * and Second Thought questions. Safe to call on every start-up: it never
     * re-enables a type an admin disabled.
     *
     * `$secondThought`: ['questions' => [...], 'locale' => 'tr' | 'en'], at most
     * two of SECOND_THOUGHT_QUESTIONS, asked on the phone before Approve. A
     * risky answer never refuses: the approval comes back `provisional` and
     * the phone asks "Was this you?" later. ['questions' => []] turns them
     * off; null keeps what the Dashboard has.
     */
    public function define(string $type, ?string $name = null, ?string $description = null, ?bool $critical = null, ?array $secondThought = null): array
    {
        $body = ['type' => $type, 'name' => $name ?? $type];
        if ($description !== null) {
            $body['description'] = $description;
        }
        if ($critical !== null) {
            $body['critical'] = $critical;
        }
        if ($secondThought !== null) {
            $body['secondThought'] = $secondThought;
        }
        return $this->http->post('/action-types', $body);
    }

    public function list(): array
    {
        return $this->http->get('/action-types');
    }
}
