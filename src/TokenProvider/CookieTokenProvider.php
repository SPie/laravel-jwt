<?php

namespace SPie\LaravelJWT\TokenProvider;

use Illuminate\Contracts\Cookie\Factory;
use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class CookieTokenProvider implements TokenProvider
{
    private Factory $cookieFactory;

    private string $key;

    public function __construct(Factory $cookieFactory)
    {
        $this->cookieFactory = $cookieFactory;
    }

    public function setKey(string $key): self
    {
        $this->key = $key;

        return $this;
    }

    public function getRequestToken(Request $request): ?string
    {
        return $request->cookies->get($this->key);
    }

    public function setResponseToken(Response $response, string $token): Response
    {
        $response->headers->setCookie($this->cookieFactory->make($this->key, $token));

        return $response;
    }
}
