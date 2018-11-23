<?php

namespace SPie\LaravelJWT\TokenProvider;

use Illuminate\Http\Request;
use SPie\LaravelJWT\Contracts\TokenProvider;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class HeaderTokenProvider
 *
 * @package SPie\LaravelJWT\TokenProvider
 */
class HeaderTokenProvider implements TokenProvider
{

    /**
     * @var string
     */
    private $key;

    /**
     * @var string|null
     */
    private $prefix;

    /**
     * HeaderTokenProvider constructor.
     *
     * @param string      $key
     * @param string|null $prefix
     */
    public function __construct(string $key, string $prefix = null)
    {
        $this->key = $key;
        $this->prefix = $prefix;
    }

    /**
     * @return string
     */
    protected function getKey(): string
    {
        return $this->key;
    }

    /**
     * @return null|string
     */
    protected function getPrefix(): ?string
    {
        return $this->prefix;
    }

    /**
     * @param Request $request
     *
     * @return null|string
     */
    public function getRequestToken(Request $request): ?string
    {
        $token = $request->header($this->getKey());
        if (empty($token)) {
            return null;
        }

        if (empty($this->getPrefix())) {
            return $token;
        }

        if (!\preg_match('/'.$this->prefix.'\s*(\S+)\b/i', $token, $matches)) {
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
        return $response->header(
            $this->getKey(),
            (!empty($this->getPrefix()) ? ($this->getPrefix() . ' ') : '') . $token
        );
    }
}