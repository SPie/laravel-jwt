<?php

namespace SPie\LaravelJWT\TokenProvider;

use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class CookieTokenProvider
 *
 * @package SPie\LaravelJWT\TokenProvider
 */
class CookieTokenProvider implements TokenProvider
{

    /**
     * @var string
     */
    private $key;

    /**
     * @param string $key
     *
     * @return CookieTokenProvider|TokenProvider
     */
    public function setKey(string $key): TokenProvider
    {
        $this->key = $key;

        return $this;
    }

    /**
     * @return string
     */
    protected function getKey(): string
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
        return $request->cookies->get($this->getKey());
    }

    /**
     * @param Response $response
     * @param string   $token
     *
     * @return Response
     */
    public function setResponseToken(Response $response, string $token): Response
    {
        $response->headers->setCookie(new Cookie($this->getKey(), $token));

        return $response;
    }
}
