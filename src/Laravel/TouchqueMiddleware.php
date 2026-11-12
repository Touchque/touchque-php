<?php

namespace Touchque\Laravel;

use Closure;
use Illuminate\Container\Container;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Touchque\Exceptions\TouchqueConfigException;
use Touchque\Guard;
use Touchque\Touchque;

/**
 * Laravel: one line per protected route.
 *
 *     Route::post('/transfer', [TransferController::class, 'store'])
 *         ->middleware('touchque:SEND_MONEY');
 *
 * Register the alias in `bootstrap/app.php` (Laravel 11+) or
 * `app/Http/Kernel.php` (`$middlewareAliases`):
 *
 *     $middleware->alias(['touchque' => \Touchque\Laravel\TouchqueMiddleware::class]);
 *
 * The client is resolved from Laravel's container on the first request, so a
 * binding of `Touchque` in a service provider is used (for your own Config: a
 * logger, a base URL), and so is a contextual one
 * (`$app->when(TouchqueMiddleware::class)->needs(Touchque::class)->give(...)`);
 * without one it is built from TQ_API_KEY / TQ_API_SECRET:
 *
 *     $this->app->singleton(Touchque::class, fn () => new Touchque());
 *
 * A missing key never throws: a guarded route answers 500 `misconfigured`
 * (401 `unauthenticated` without a signed-in user) and never runs, and the
 * middleware logs it once through Laravel's logger.
 *
 * Until the user approves on their phone this answers
 * `202 {"touchque": step, "token": "..."}`. Your page shows the step in its
 * own design and sends the same request again with header
 * `X-Touchque-Token: <token>`. Once approved the route runs ONCE, with
 * `$request->touchque` set to the approval.
 *
 * What the phone shows (an amount, a payee): put the name of a Request
 * macro (or a method of your Request class) after the action; the array it
 * returns is shown and bound to the approval. A name that is neither
 * answers 500 `misconfigured`:
 *
 *     Request::macro('transferDetails', fn () => ['Amount' => request('amount') . ' EUR']);
 *     ->middleware('touchque:SEND_MONEY,transferDetails');
 *
 * The signed-in user comes from Laravel's own auth (`$request->user()`,
 * tried as `->email`, `->getAuthIdentifier()`, `->username`). For the login
 * route (no signed-in user yet), extend this class and override
 * `resolveUser()` to return whoever just passed your password check.
 *
 * Silent sign-ins (default off): with `silentSignIn` on, a new attempt whose
 * browser sent its device-bound key proof (`X-Touchque-Browser`, added by
 * `@touchque/web` with `browserKey: true`) first asks Touchque whether
 * anything about it is new. If nothing is, the route runs at once with no
 * push (`touchque` approval with `assurance.method` `silent` and `reasons`).
 * Otherwise, and on any error, the usual push starts and its approval makes
 * the browser known. Turn it on in a subclass
 * (`protected $silentSignIn = true;`) or when binding the middleware:
 *
 *     $this->app->bind(TouchqueMiddleware::class, fn () => new TouchqueMiddleware(
 *         null, ['silentSignIn' => ['maxAgeSeconds' => 8 * 3600]]));
 *
 * Every answer of 400 and above carries `X-Touchque-State` (and
 * `X-Touchque-Reason` when the step has a reason).
 *
 * Your own error shape (`errorBody`): every answer of 400 and above (401, 403,
 * 408, 423, 429, 500, 503; never a 202 step, never an approval) is built by
 * your callable from the refusal (`Guard::refusal()`: `status`, `code`,
 * `message`, `touchque`). What it encodes to, as JsonResponse encodes it
 * (Jsonable, Arrayable, JsonSerializable…), decides: a JSON object is sent with
 * `touchque` set to the step; anything else as it is. Status and headers stay
 * the same; a callable that throws, or a result that cannot be encoded, is
 * logged and the default body sent:
 *
 *     $this->app->bind(TouchqueMiddleware::class, fn () => new TouchqueMiddleware(null, [
 *         'errorBody' => fn (array $r) => ['message' => $r['message'], 'code' => $r['code']],
 *     ]));
 */
class TouchqueMiddleware
{
    /** Built on the first request when not given. */
    private ?Touchque $touchque;

    /**
     * Silent sign-ins: `false` (default), `true`, or `['maxAgeSeconds' => int]`
     * for your own limit on how long ago the last phone approval in that
     * browser may be (0 = always ask).
     *
     * @var bool|array
     */
    protected $silentSignIn = false;

    /**
     * For your Touchque Actions only (`event.context`): a callable taking the
     * Request and returning an array (roles, plan, amount…). Never shown on
     * the phone. Or override `resolveContext()`.
     *
     * @var callable|null
     */
    protected $context = null;

    /**
     * Your own error shape: a callable taking the refusal of an answer with
     * status >= 400 (`['status', 'code', 'message', 'touchque']`) and returning
     * the body. Set it with the `errorBody` option, or in your subclass's
     * constructor.
     *
     * @var callable|null
     */
    protected $errorBody = null;

    /**
     * @param Touchque|null $touchque the client; null (the default) resolves it
     *   from Laravel's container (your binding, or TQ_API_KEY / TQ_API_SECRET) on
     *   the first request, where a missing key is an answer, not an exception.
     * @param array $options ['silentSignIn' => bool|array, 'context' => callable(Request): array,
     *   'errorBody' => callable(array $refusal): mixed]
     */
    public function __construct($touchque = null, array $options = [])
    {
        if ($touchque !== null && !$touchque instanceof Touchque) {
            throw new \InvalidArgumentException('TouchqueMiddleware: the client must be a Touchque instance or null.');
        }
        $this->touchque = $touchque;
        if (isset($options['context'])) {
            $this->context = $options['context'];
        }
        if (array_key_exists('silentSignIn', $options)) {
            $this->silentSignIn = $options['silentSignIn'];
        }
        if (isset($options['errorBody'])) {
            $this->errorBody = $options['errorBody'];
        }
        Guard::assertSilentSignInOption($this->silentSignIn, 'TouchqueMiddleware');
        if ($this->errorBody !== null && !is_callable($this->errorBody)) {
            throw new \InvalidArgumentException('TouchqueMiddleware: "errorBody" must be callable.');
        }
    }

    public function handle(Request $request, Closure $next, string $action, ?string $detailsMethod = null)
    {
        $user = $this->resolveUser($request);
        try {
            $touchque = $this->client();
        } catch (TouchqueConfigException $err) {
            // Logged once per process, shared with Guard::run(null, ...).
            Guard::logUnconfigured($err);
            return $this->respond($user ? Guard::misconfigured() : Guard::unauthenticated());
        }

        $details = null;
        if ($detailsMethod) {
            // A Request macro (Request::macro('transferDetails', ...)) is how a route usually adds
            // one; method_exists() does not see macros. A name that is neither must not approve
            // without the details the route meant the phone to show.
            if (!method_exists($request, $detailsMethod) && !$request::hasMacro($detailsMethod)) {
                $touchque->log('error', "[Touchque] TouchqueMiddleware: the Request has no method or macro \"{$detailsMethod}\" for the details");
                return $this->respond(Guard::misconfigured());
            }
            $details = $request->{$detailsMethod}();
        }

        $header = fn (string $name) => $request->header($name);
        $input = Guard::inputFromHeaders($header);
        $silent = Guard::silentInputFromHeaders($this->silentSignIn, $header);

        $result = Guard::run(
            $touchque,
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

        return $this->respond($result);
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

    /** What your Touchque Actions get as `event.context` (default: the `context` option, or none). */
    protected function resolveContext(Request $request): ?array
    {
        return $this->context ? ($this->context)($request) : null;
    }

    /**
     * The client given, else Laravel's container `Touchque` (your binding, or one
     * built from TQ_API_KEY / TQ_API_SECRET), kept once built. Throws
     * TouchqueConfigException when it cannot be built.
     */
    private function client(): Touchque
    {
        if ($this->touchque === null) {
            $this->touchque = class_exists(Container::class)
                ? $this->fromContainer(Container::getInstance())
                : new Touchque();
        }
        return $this->touchque;
    }

    /**
     * What constructor injection gave before 5.1: a contextual binding for this
     * middleware (`$app->when(TouchqueMiddleware::class)->needs(Touchque::class)`),
     * else the container's `Touchque`.
     */
    private function fromContainer(Container $app): Touchque
    {
        foreach (array_unique([static::class, self::class]) as $class) {
            // Public in Laravel 9-11; `??` reads it as missing anywhere it is not.
            $given = $app->contextual[$class][Touchque::class] ?? null;
            if ($given instanceof Closure) {
                return $given($app, []);
            }
            if (is_string($given)) {
                return $app->make($given);
            }
            if ($given instanceof Touchque) {
                return $given;
            }
        }
        return $app->make(Touchque::class);
    }

    /** The JSON answer for a result that is not an approval: Guard::response() with your errorBody. */
    private function respond(array $result): JsonResponse
    {
        $errorBody = $this->errorBody;
        $answer = Guard::response(
            $result,
            $errorBody === null ? null : static fn (array $refusal) => self::asJsonResponseEncodes($errorBody($refusal)),
            $this->touchque
        );
        if ($answer['body'] === null) {
            // Encoded here so that null is sent as null (JsonResponse would send {}).
            return new JsonResponse('null', $answer['status'], $answer['headers'], 0, true);
        }
        // The same bytes, and getOriginalContent() is the body.
        return new JsonResponse($answer['body'], $answer['status'], $answer['headers']);
    }

    /**
     * An errorBody result in the form JsonResponse encodes it: a Jsonable as its
     * JSON (objects stay objects), a JsonSerializable as it is, an Arrayable as its
     * array. Guard::errorBody() then decides by the JSON.
     *
     * @param mixed $value
     * @return mixed
     */
    private static function asJsonResponseEncodes($value)
    {
        if (interface_exists(Jsonable::class) && $value instanceof Jsonable) {
            return json_decode($value->toJson(), false, 512, JSON_THROW_ON_ERROR);
        }
        if ($value instanceof \JsonSerializable) {
            return $value;
        }
        if (interface_exists(Arrayable::class) && $value instanceof Arrayable) {
            return $value->toArray();
        }
        return $value;
    }
}
