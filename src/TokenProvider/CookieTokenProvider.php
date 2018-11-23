<?php

namespace SPie\LaravelJWT\TokenProvider;

use Illuminate\Http\Request;
use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Cookie;
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
     * CookieTokenProvider constructor.
     *
     * @param string      $key
     * @param string|null $prefix
     */
    public function __construct(string $key, string $prefix = null)
    {
        $this->key = $key;
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
        return $request->cookie($this->getKey());
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