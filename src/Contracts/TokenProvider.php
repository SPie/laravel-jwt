<?php

namespace SPie\LaravelJWT\Contracts;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Interface JWTProvider
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface TokenProvider
{

    /**
     * @param string $key
     *
     * @return TokenProvider
     */
    public function setKey(string $key): self;

    /**
     * @param Request $request
     *
     * @return null|string
     */
    public function getRequestToken(Request $request): ?string;

    /**
     * @param Response $response
     * @param string   $token
     *
     * @return Response
     */
    public function setResponseToken(Response $response, string $token): Response;
}
