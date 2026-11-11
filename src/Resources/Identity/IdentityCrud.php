<?php

namespace Touchque\Resources\Identity;

use Touchque\Http\HttpClient;

/** List, get, create, update and delete for one kind of Touchque Login object. */
class IdentityCrud
{
    protected HttpClient $http;
    protected string $base;
    private string $listKey;

    public function __construct(HttpClient $http, string $base, string $listKey)
    {
        $this->http = $http;
        $this->base = $base;
        $this->listKey = $listKey;
    }

    public function list(array $params = []): array
    {
        return $this->http->get($this->base, $params)[$this->listKey] ?? [];
    }

    public function get(string $id): array
    {
        return $this->http->get($this->base . '/' . rawurlencode($id));
    }

    public function create(array $body): array
    {
        return $this->http->post($this->base, $body);
    }

    public function update(string $id, array $body): array
    {
        return $this->http->patch($this->base . '/' . rawurlencode($id), $body);
    }

    public function delete(string $id): array
    {
        return $this->http->delete($this->base . '/' . rawurlencode($id));
    }
}
