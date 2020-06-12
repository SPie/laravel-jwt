<?php

namespace SPie\LaravelJWT\Events;

use SPie\LaravelJWT\Contracts\JWT;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;

/**
 * Class Login
 *
 * @package SPie\LaravelJWT\Events
 */
final class Login implements Event, IpAddressable
{
    use IpAddress;

    /**
     * @var JWTAuthenticatable
     */
    private JWTAuthenticatable $user;

    /**
     * @var JWT
     */
    private JWT $accessToken;

    /**
     * LoginEvent constructor.
     *
     * @param JWTAuthenticatable $user
     * @param JWT                $accessToken
     * @param string|null        $ipAddress
     */
    public function __construct(JWTAuthenticatable $user, JWT $accessToken, string $ipAddress = null)
    {
        $this->user = $user;
        $this->accessToken = $accessToken;
        $this->ipAddress = $ipAddress;
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
