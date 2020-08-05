<?php

namespace SPie\LaravelJWT\TokenProvider;

use Illuminate\Contracts\Cookie\Factory;
use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class CookieTokenProvider
 *
 * @package SPie\LaravelJWT\TokenProvider
 */
final class CookieTokenProvider implements TokenProvider
{
    /**
     * @var Factory
     */
    private Factory $cookieFactory;

    /**
     * @var string
     */
    private string $key;

    /**
     * CookieTokenProvider constructor.
     *
     * @param Factory $cookieFactory
     */
    public function __construct(Factory $cookieFactory)
    {
        $this->cookieFactory = $cookieFactory;
    }

    /**
     * @return Factory
     */
    private function getCookieFactory(): Factory
    {
        return $this->cookieFactory;
    }

    /**
     * @param string $key
     *
     * @return CookieTokenProvider
     */
    public function setKey(string $key): self
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
        $response->headers->setCookie($this->getCookieFactory()->make($this->getKey(), $token));

        return $response;
    }
}
