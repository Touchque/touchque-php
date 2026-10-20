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
 *
 * Silent sign-ins (default off): with `silentSignIn` on, a new attempt whose
 * browser sent its device-bound key proof (`X-TouchQue-Browser`, added by
 * `@touchque/web` with `browserKey: true`) first asks TouchQue whether
 * anything about it is new. If nothing is, the route runs at once with no
 * push (`touchque` approval with `assurance.method` `silent` and `reasons`).
 * Otherwise, and on any error, the usual push starts and its approval makes
 * the browser known. Turn it on in a subclass
 * (`protected $silentSignIn = true;`) or when binding the middleware:
 *
 *     $this->app->bind(TouchQueMiddleware::class, fn ($app) => new TouchQueMiddleware(
 *         $app->make(TouchQue::class), ['silentSignIn' => ['maxAgeSeconds' => 8 * 3600]]));
 */
class TouchQueMiddleware
{
    private TouchQue $touchQue;

    /**
     * Silent sign-ins: `false` (default), `true`, or `['maxAgeSeconds' => int]`
     * for your own limit on how long ago the last phone approval in that
     * browser may be (0 = always ask).
     *
     * @var bool|array
     */
    protected $silentSignIn = false;

    /**
     * For your TouchQue Actions only (`event.context`): a callable taking the
     * Request and returning an array (roles, plan, amount…). Never shown on
     * the phone. Or override `resolveContext()`.
     *
     * @var callable|null
     */
    protected $context = null;

    /** @param array $options ['silentSignIn' => bool|array, 'context' => callable(Request): array] */
    public function __construct(TouchQue $touchQue, array $options = [])
    {
        $this->touchQue = $touchQue;
        if (isset($options['context'])) {
            $this->context = $options['context'];
        }
        if (array_key_exists('silentSignIn', $options)) {
            $this->silentSignIn = $options['silentSignIn'];
        }
        Guard::assertSilentSignInOption($this->silentSignIn, 'TouchQueMiddleware');
    }

    public function handle(Request $request, Closure $next, string $action, ?string $detailsMethod = null)
    {
        $user = $this->resolveUser($request);
        $details = $detailsMethod && method_exists($request, $detailsMethod) ? $request->{$detailsMethod}() : null;

        $header = fn (string $name) => $request->header($name);
        $input = Guard::inputFromHeaders($header);
        $silent = Guard::silentInputFromHeaders($this->silentSignIn, $header);

        $result = Guard::run(
            $this->touchQue,
            $user,
            $action,
            $details,
            null,
            $request->ip(),
            $request->userAgent(),
            $input['token'],
            $input['offline'],
            $input['code'],
            $input['codeType'],
            true,
            $silent['browserProof'],
            $silent['silentSignIn'],
            $this->resolveContext($request)
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

    /** What your TouchQue Actions get as `event.context` (default: the `context` option, or none). */
    protected function resolveContext(Request $request): ?array
    {
        return $this->context ? ($this->context)($request) : null;
    }
}
