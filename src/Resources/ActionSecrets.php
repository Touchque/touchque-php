<?php

namespace TouchQue\Resources;

use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Http\HttpClient;

/**
 * Secrets your TouchQue Actions read (`event.secrets.NAME`) or notify with.
 * A value is encrypted and never readable again through the API.
 */
class ActionSecrets
{
    private HttpClient $http;

    public function __construct(HttpClient $http)
    {
        $this->http = $http;
    }

    public function set(string $name, string $value): array
    {
        if ($value === '') {
            throw new TouchQueConfigException('A secret value is a non-empty string');
        }
        return $this->http->put(self::path($name), ['value' => $value]);
    }

    /** Names only. */
    public function list(): array
    {
        return $this->http->get('/actions/secrets')['secrets'] ?? [];
    }

    public function delete(string $name): array
    {
        return $this->http->delete(self::path($name));
    }

    private static function path(string $name): string
    {
        if (!preg_match('/^[A-Z][A-Z0-9_]{0,63}$/', $name)) {
            throw new TouchQueConfigException('A secret name is capital letters, digits or _ (e.g. SLACK_WEBHOOK_URL)');
        }
        return '/actions/secrets/' . $name;
    }
}
