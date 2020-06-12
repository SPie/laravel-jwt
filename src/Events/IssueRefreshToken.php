<?php

namespace SPie\LaravelJWT\Events;

use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;

/**
 * Class IssueRefreshToken
 *
 * @package SPie\LaravelJWT\Events
 */
class IssueRefreshToken implements Event
{

    /**
     * @var JWTAuthenticatable
     */
    private JWTAuthenticatable $user;

    /**
     * @var JWT
     */
    private JWT $accessToken;

    /**
     * @var JWT
     */
    private JWT $refreshToken;

    /**
     * IssueRefreshToken constructor.
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
