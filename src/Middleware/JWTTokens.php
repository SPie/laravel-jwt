<?php

namespace SPie\LaravelJWT\Middleware;

use SPie\LaravelJWT\Contracts\JWTGuard;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class JWTTokens
{
    private JWTGuard $jwtGuard;

    public function __construct(JWTGuard $jwtGuard)
    {
        $this->jwtGuard = $jwtGuard;
    }

    /**
     * @return Response
     */
    public function handle(Request $request, \Closure $next)
    {
        return $this->jwtGuard->returnTokens($next($request));
    }
}
