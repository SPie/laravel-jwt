<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Contracts\Auth\StatefulGuard;
use Symfony\Component\HttpFoundation\Response;

interface JWTGuard extends StatefulGuard
{
    public function getAccessToken(): ?JWT;

    public function getRefreshToken(): ?JWT;

    public function returnTokens(Response $response): Response;
}
