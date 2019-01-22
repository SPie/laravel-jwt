<?php

use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class TestTokenProvider
 */
class TestTokenProvider implements TokenProvider
{

    /**
     * @var string|null
     */
    private $token;

    /**
     * @param string|null $token
     *
     * @return TestTokenProvider
     */
    public function setToken(?string $token): TestTokenProvider
    {
        $this->token = $token;

        return $this;
    }

    /**
     * @return string|null
     */
    public function getToken(): ?string
    {
        return $this->token;
    }

    /**
     * @param Request $request
     *
     * @return null|string
     */
    public function getRequestToken(Request $request): ?string
    {
        return $this->getToken();
    }

    /**
     * @param Response $response
     * @param string   $token
     *
     * @return Response
     */
    public function setResponseToken(Response $response, string $token): Response {}

    /**
     * @param string $key
     *
     * @return TokenProvider
     */
    public function setKey(string $key): TokenProvider
    {
        // TODO: Implement setKey() method.
    }
}
