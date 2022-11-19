<?php

namespace SPie\LaravelJWT\Contracts;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

interface TokenProvider
{
    public function setKey(string $key): self;

    public function getRequestToken(Request $request): ?string;

    public function setResponseToken(Response $response, string $token): Response;
}
