<?php

namespace SPie\LaravelJWT\Events;

use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;

/**
 * Class Login
 *
 * @package SPie\LaravelJWT\Events
 */
final class Login implements Event
{

    /**
     * @var JWTAuthenticatable
     */
    private $user;

    /**
     * @var JWT
     */
    private $accessToken;

    /**
     * @var array
     */
    private $credentials;

    /**
     * LoginEvent constructor.
     *
     * @param JWTAuthenticatable $user
     * @param JWT                $accessToken
     * @param array              $credentials
     */
    public function __construct(JWTAuthenticatable $user, JWT $accessToken, array $credentials = [])
    {
        $this->user = $user;
        $this->accessToken = $accessToken;
        $this->credentials = $credentials;
    }

    /**
     * @return JWTAuthenticatable
     */
    public function getUser(): JWTAuthenticatable
    {
        return $this->user;
    }

    /**
     * @return JWT
     */
    public function getAccessToken(): JWT
    {
        return $this->accessToken;
    }

    /**
     * @return array
     */
    public function getCredentials(): array
    {
        return $this->credentials;
    }
}
