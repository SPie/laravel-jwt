<?php

namespace SPie\LaravelJWT\TokenProvider;

use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class HeaderTokenProvider implements TokenProvider
{
    const BEARER_PREFIX = 'Bearer';

    private string $key;

    public function setKey(string $key): self
    {
        $this->key = $key;

        return $this;
    }

    public function getRequestToken(Request $request): ?string
    {
        $token = $request->headers->get($this->key);
        if (empty($token)) {
            return null;
        }

        if (!\preg_match('/' . self::BEARER_PREFIX . '\s*(\S+)\b/i', $token, $matches)) {
            return null;
        }

        return $matches[1];
    }

    public function setResponseToken(Response $response, string $token): Response
    {
        $response->headers->set($this->key, self::BEARER_PREFIX . ' ' . $token);

        return $response;
    }
}
