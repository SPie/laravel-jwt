<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Contracts\Auth\Guard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Interface JWTGuard
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface JWTGuard extends Guard
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
     * @param JWTAuthenticatable $user
     *
     * @return JWT
     */
    public function issueAccessToken(JWTAuthenticatable $user): JWT;

    /**
     * @param array $credentials
     *
     * @return JWTGuard
     */
    public function login(array $credentials = []): JWTGuard;

    /**
     * @return JWTGuard
     */
    public function logout(): JWTGuard;

    /**
     * @return JWT
     */
    public function issueRefreshToken(): JWT;

    /**
     * @return JWT
     */
    public function refreshAccessToken(): JWT;

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
