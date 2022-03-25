<?php

namespace SPie\LaravelJWT\TokenProvider;

use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class JsonTokenProvider implements TokenProvider
{
    private ?string $key = null;

    public function setKey(string $key): self
    {
        $this->key = $key;

        return $this;
    }

    public function getRequestToken(Request $request): ?string
    {
        return $request->get($this->key);
    }

    public function setResponseToken(Response $response, string $token): Response
    {
        $content = \json_decode($response->getContent(), true);
        if ($content === null) {
            return $response;
        }

        $content[$this->key] = $token;

        return $response->setContent($content);
    }
}
