<?php

namespace SPie\LaravelJWT\Middleware;

use SPie\LaravelJWT\Contracts\JWTGuard;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class JWTTokens
 *
 * @package SPie\LaravelJWT\Middleware
 */
final class JWTTokens
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
        return $this->getJwtGuard()->returnTokens($next($request));
    }
}
