<?php

namespace SPie\LaravelJWT\Middleware;

use Illuminate\Contracts\Auth\Factory;
use SPie\LaravelJWT\Contracts\JWTGuard;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class AuthReturnMiddleware
 *
 * @package SPie\LaravelJWT\Middleware
 */
final class AuthReturnMiddleware
{
    use Authenticated;

    /**
     * @var Factory
     */
    private Factory $authFactory;

    /**
     * AuthReturnMiddleware constructor.
     *
     * @param Factory $authFactory
     */
    public function __construct(Factory $authFactory)
    {
        $this->authFactory = $authFactory;
    }

    /**
     * @return Factory
     */
    private function getAuthFactory(): Factory
    {
        return $this->authFactory;
    }

    /**
     * @param Request     $request
     * @param \Closure    $next
     * @param string|null $guard
     *
     * @return mixed
     */
    public function handle(Request $request, \Closure $next, string $guard = null)
    {
        $authGuard = $this->getAuthFactory()->guard($guard);

        return $this
            ->checkAuthenticated($authGuard)
            ->addTokensToResponse($authGuard, $next($request));
    }

    /**
     * @param JWTGuard $authGuard
     * @param Response $response
     *
     * @return Response
     */
    private function addTokensToResponse(JWTGuard $authGuard, Response $response)
    {
        try {
            $response = $authGuard->returnRefreshToken($response);
        } catch (NotAuthenticatedException $e) {
        }

        return $authGuard->returnAccessToken($response);
    }
}
