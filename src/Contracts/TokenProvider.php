<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Interface JWTProvider
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface TokenProvider
{


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
