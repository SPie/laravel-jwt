<?php

namespace SPie\LaravelJWT\TokenProvider;

use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class HeaderTokenProvider
 *
 * @package SPie\LaravelJWT\TokenProvider
 */
final class HeaderTokenProvider implements TokenProvider
{

    const BEARER_PREFIX = 'Bearer';

    /**
     * @var string
     */
    private $key;

    /**
     * @param string $key
     *
     * @return HeaderTokenProvider|TokenProvider
     */
    public function setKey(string $key): TokenProvider
    {
        $this->key = $key;

        return $this;
    }

    /**
     * @return string
     */
    private function getKey(): string
    {
        return $this->key;
    }

    /**
     * @param Request $request
     *
     * @return null|string
     */
    public function getRequestToken(Request $request): ?string
    {
        $token = $request->headers->get($this->getKey());
        if (empty($token)) {
            return null;
        }

        if (!\preg_match('/' . self::BEARER_PREFIX . '\s*(\S+)\b/i', $token, $matches)) {
            return null;
        }

        return $matches[1];
    }

    /**
     * @param Response $response
     * @param string   $token
     *
     * @return Response
     */
    public function setResponseToken(Response $response, string $token): Response
    {
        $response->headers->set($this->getKey(), self::BEARER_PREFIX . ' ' . $token);

        return $response;
    }
}
