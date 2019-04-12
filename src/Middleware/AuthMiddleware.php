<?php

namespace SPie\LaravelJWT\Middleware;

use Illuminate\Contracts\Auth\Factory;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class AuthMiddleware
 *
 * @package SPie\LaravelJWT\Middleware
 */
final class AuthMiddleware
{

    /**
     * @var Factory
     */
    private $authFactory;

    /**
     * AuthMiddleware constructor.
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
    protected function getAuthFactory(): Factory
    {
        return $this->authFactory;
    }

    /**
     * @param Request     $request
     * @param \Closure    $next
     * @param string|null $guard
     *
     * @return mixed
     *
     * @throws NotAuthenticatedException
     */
    public function handle(Request $request, \Closure $next, string $guard = null)
    {
        if ($this->getAuthFactory()->guard($guard)->guest()) {
            throw new NotAuthenticatedException();
        }

        return $next($request);
    }
}
