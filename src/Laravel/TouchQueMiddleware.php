<?php

namespace TouchQue\Laravel;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use TouchQue\Guard;
use TouchQue\TouchQue;

/**
 * Laravel: one line per protected route.
 *
 *     Route::post('/transfer', [TransferController::class, 'store'])
 *         ->middleware('touchque:SEND_MONEY');
 *
 * Register the alias in `bootstrap/app.php` (Laravel 11+) or
 * `app/Http/Kernel.php` (`$middlewareAliases`):
 *
 *     $middleware->alias(['touchque' => \TouchQue\Laravel\TouchQueMiddleware::class]);
 *
 * `TouchQue` is constructor-injected, so Laravel's container resolves it
 * automatically — bind it once in a service provider:
 *
 *     $this->app->singleton(TouchQue::class, fn () => new TouchQue());
 *
 * Until the user approves on their phone this answers
 * `202 {"touchque": step, "token": "..."}`. Your page shows the step in its
 * own design and sends the same request again with header
 * `X-TouchQue-Token: <token>`. Once approved the route runs ONCE, with
 * `$request->touchque` set to the approval.
 *
 * The signed-in user comes from Laravel's own auth (`$request->user()`,
 * tried as `->email`, `->getAuthIdentifier()`, `->username`). For the login
 * route (no signed-in user yet), extend this class and override
 * `resolveUser()` to return whoever just passed your password check.
 */
class TouchQueMiddleware
{
    private TouchQue $touchQue;

    public function __construct(TouchQue $touchQue)
    {
        $this->touchQue = $touchQue;
    }

    public function handle(Request $request, Closure $next, string $action, ?string $detailsMethod = null)
    {
        $user = $this->resolveUser($request);
        $details = $detailsMethod && method_exists($request, $detailsMethod) ? $request->{$detailsMethod}() : null;

        $result = Guard::run(
            $this->touchQue,
            $user,
            $action,
            $details,
            null,
            $request->ip(),
            $request->userAgent(),
            ...array_values(Guard::inputFromHeaders(fn (string $name) => $request->header($name)))
        );

        if (isset($result['approved'])) {
            // $request->attributes->get('touchque') in your route — Request
            // doesn't declare a $touchque property, so we don't set one dynamically.
            $request->attributes->set('touchque', $result['approved']);
            return $next($request);
        }

        $headers = ['Cache-Control' => 'no-store'];
        if (!empty($result['body']['touchque']['retryAfter'])) {
            $headers['Retry-After'] = (string)$result['body']['touchque']['retryAfter'];
        }
        return new JsonResponse($result['body'], $result['status'], $headers);
    }

    /**
     * Who is approving. Default: the authenticated user's email, auth
     * identifier, or username. Override in a subclass for the login step,
     * where you should return the user who just passed your password check
     * instead of `$request->user()`.
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
