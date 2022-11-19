<?php

namespace SPie\LaravelJWT\Test;

use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class TestTokenProvider implements TokenProvider
{
    private ?string $key;

    private ?string $token;

    public function setToken(?string $token): TestTokenProvider
    {
        $this->token = $token;
        $this->key = null;

        return $this;
    }

    public function getToken(): ?string
    {
        return $this->token;
    }

    public function getRequestToken(Request $request): ?string
    {
        return $this->token;
    }

    public function setResponseToken(Response $response, string $token): Response
    {
    }

    public function setKey(string $key): TokenProvider
    {
        $this->key = $key;

        return $this;
    }

    public function getKey(): ?string
    {
        return $this->key;
    }
}
