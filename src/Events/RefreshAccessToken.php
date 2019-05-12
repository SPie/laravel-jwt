<?php

namespace SPie\LaravelJWT\Events;

use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;

/**
 * Class RefreshAccessToken
 *
 * @package SPie\LaravelJWT\Events
 */
class RefreshAccessToken implements Event
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
     * @var JWT
     */
    private $refreshToken;

    /**
     * RefreshAccessToken constructor.
     *
     * @param JWTAuthenticatable $user
     * @param JWT                $accessToken
     * @param JWT                $refreshToken
     */
    public function __construct(JWTAuthenticatable $user, JWT $accessToken, JWT $refreshToken)
    {
        $this->user = $user;
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
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
     * @return JWT
     */
    public function getRefreshToken(): JWT
    {
        return $this->refreshToken;
    }
}