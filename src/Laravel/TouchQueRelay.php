<?php

namespace TouchQue\Laravel;

use Illuminate\Contracts\Routing\Registrar;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use TouchQue\Relay\RelayHandler;
use TouchQue\Relay\RelayResponse;
use TouchQue\TouchQue;

/**
 * Laravel: every relay route a frontend (`@touchque/web`) needs — POST /login,
 * enrollment, offline codes, passkey ceremonies — as one controller. See
 * `TouchQue\Relay\RelayHandler` for the routes, options and security rules.
 *
 * Bind it once in a service provider with your options (the callables get the
 * Illuminate `Request`; `onAuthenticated` also gets the pending
 * `RelayResponse`, whose headers you may change):
 *
 *     $this->app->singleton(TouchQueRelay::class, fn ($app) => new TouchQueRelay($app->make(TouchQue::class), [
 *         'getLoginUser' => fn (Request $r) => $r->session()->get('password_verified_user'),
 *         'onAuthenticated' => function (Request $r, RelayResponse $res, array $info) {
 *             $r->session()->regenerate();
 *             $r->session()->put('touchque_user', $info['externalUsername']);
 *         },
 *     ]));
 *
 * and register the routes, e.g. in routes/web.php (session middleware needed
 * for getLoginUser/onAuthenticated):
 *
 *     TouchQueRelay::routes(app('router'), 'touchque');
 *
 * Routes point at this class (no closures), so `php artisan route:cache` works.
 * Without a `getUserId` option the signed-in user comes from Laravel's own auth
 * (`$request->user()`, tried as `->email`, `->getAuthIdentifier()`, `->username`),
 * like TouchQueMiddleware. `$request->ip()` must be the real client: configure
 * TrustProxies behind a load balancer.
 */
class TouchQueRelay
{
    private RelayHandler $handler;

    public function __construct(TouchQue $touchQue, array $options = [])
    {
        if (!isset($options['getUserId'])) {
            $options['getUserId'] = function (Request $request): ?string {
                return $this->resolveUser($request);
            };
        }
        $this->handler = new RelayHandler($touchQue, $options);
    }

    /**
     * Registers the 14 relay routes under $prefix on a Laravel router
     * (`app('router')`, or the `$router` a `Route::group()` closure receives).
     */
    public static function routes(Registrar $router, string $prefix = 'touchque'): void
    {
        $p = trim($prefix, '/');
        $p = $p === '' ? '' : '/' . $p;
        $c = static::class;

        $router->post($p . '/enroll/start', [$c, 'enrollStart']);
        $router->get($p . '/enroll/status', [$c, 'enrollStatus']);
        $router->post($p . '/login', [$c, 'login']);
        $router->post($p . '/offline/challenge', [$c, 'offlineChallenge']);
        $router->post($p . '/offline/verify', [$c, 'offlineVerify']);
        $router->post($p . '/offline/totp', [$c, 'offlineTotp']);
        $router->post($p . '/passkey/authenticate/options', [$c, 'passkeyAuthenticateOptions']);
        $router->post($p . '/passkey/authenticate/verify', [$c, 'passkeyAuthenticateVerify']);
        $router->post($p . '/passkey/login/options', [$c, 'passkeyLoginOptions']);
        $router->post($p . '/passkey/login/verify', [$c, 'passkeyLoginVerify']);
        $router->post($p . '/passkey/register/options', [$c, 'passkeyRegisterOptions']);
        $router->post($p . '/passkey/register/verify', [$c, 'passkeyRegisterVerify']);
        $router->get($p . '/passkey/credentials', [$c, 'passkeyCredentials']);
        $router->delete($p . '/passkey/credentials/{id}', [$c, 'deleteCredential']);
    }

    public function enrollStart(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/enroll/start');
    }

    public function enrollStatus(Request $request): JsonResponse
    {
        return $this->relay($request, 'GET', '/enroll/status');
    }

    public function login(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/login');
    }

    public function offlineChallenge(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/offline/challenge');
    }

    public function offlineVerify(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/offline/verify');
    }

    public function offlineTotp(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/offline/totp');
    }

    public function passkeyAuthenticateOptions(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/passkey/authenticate/options');
    }

    public function passkeyAuthenticateVerify(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/passkey/authenticate/verify');
    }

    public function passkeyLoginOptions(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/passkey/login/options');
    }

    public function passkeyLoginVerify(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/passkey/login/verify');
    }

    public function passkeyRegisterOptions(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/passkey/register/options');
    }

    public function passkeyRegisterVerify(Request $request): JsonResponse
    {
        return $this->relay($request, 'POST', '/passkey/register/verify');
    }

    public function passkeyCredentials(Request $request): JsonResponse
    {
        return $this->relay($request, 'GET', '/passkey/credentials');
    }

    public function deleteCredential(Request $request, string $id): JsonResponse
    {
        return $this->relay($request, 'DELETE', '/passkey/credentials/' . rawurlencode($id));
    }

    /** Runs one relay route for a Laravel request and returns Laravel's JSON response. */
    public function relay(Request $request, string $method, string $path): JsonResponse
    {
        // JSON bodies only, like the Node router behind express.json().
        $body = $request->isJson() ? $request->json()->all() : [];
        $res = $this->handler->handle(
            $method,
            $path,
            is_array($body) ? $body : [],
            (string)$request->ip(),
            $request->userAgent(),
            function (string $name) use ($request): ?string {
                $value = $request->header($name);
                return is_string($value) ? $value : null;
            },
            $request
        );
        if ($res === null) {
            return new JsonResponse(['error' => 'not_found'], 404);
        }
        return self::toJsonResponse($res);
    }

    public static function toJsonResponse(RelayResponse $res): JsonResponse
    {
        $body = $res->getBody();
        return new JsonResponse($body === [] ? new \stdClass() : $body, $res->getStatus(), $res->getHeaders());
    }

    /**
     * The signed-in user when no `getUserId` option is given. Default: the
     * authenticated user's email, auth identifier, or username.
     */
    protected function resolveUser(Request $request): ?string
    {
        $user = $request->user();
        if (!$user) {
            return null;
        }
        return $user->email ?? (method_exists($user, 'getAuthIdentifier') ? (string)$user->getAuthIdentifier() : null) ?? $user->username ?? null;
    }
}
