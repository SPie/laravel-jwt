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
     * LoginEvent constructor.
     *
     * @param JWTAuthenticatable $user
     * @param JWT                $accessToken
     */
    public function __construct(JWTAuthenticatable $user, JWT $accessToken)
    {
        $this->user = $user;
        $this->accessToken = $accessToken;
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
}
