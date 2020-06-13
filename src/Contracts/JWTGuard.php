<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Contracts\Auth\StatefulGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Interface JWTGuard
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface JWTGuard extends StatefulGuard
{

    /**
     * @return JWT|null
     */
    public function getAccessToken(): ?JWT;

    /**
     * @return JWT|null
     */
    public function getRefreshToken(): ?JWT;

    /**
     * @param Response $response
     *
     * @return Response
     */
    public function returnAccessToken(Response $response): Response;

    /**
     * @param Response $response
     *
     * @return Response
     */
    public function returnRefreshToken(Response $response): Response;
}
