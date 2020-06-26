<?php

namespace SPie\LaravelJWT\Middleware;

use Illuminate\Auth\AuthenticationException;
use SPie\LaravelJWT\Contracts\JWTGuard;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class JWTAuthentication
 *
 * @package SPie\LaravelJWT\Middleware
 */
final class JWTAuthentication
{
    /**
     * @var JWTGuard
     */
    private JWTGuard $jwtGuard;

    /**
     * JWTAuthentication constructor.
     *
     * @param JWTGuard $jwtGuard
     */
    public function __construct(JWTGuard $jwtGuard)
    {
        $this->jwtGuard = $jwtGuard;
    }

    /**
     * @return JWTGuard
     */
    private function getJwtGuard(): JWTGuard
    {
        return $this->jwtGuard;
    }

    /**
     * @param Request  $request
     * @param \Closure $next
     *
     * @return mixed
     */
    public function handle(Request $request, \Closure $next)
    {
        if ($this->getJwtGuard()->guest()) {
            throw new AuthenticationException();
        }

        return $this->getJwtGuard()->returnTokens($next($request));
    }
}
