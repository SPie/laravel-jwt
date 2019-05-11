<?php

namespace SPie\LaravelJWT\Events;

use SPie\LaravelJWT\Contracts\JWTAuthenticatable;

/**
 * Class Logout
 *
 * @package SPie\LaravelJWT\Events
 */
final class Logout implements Event
{

    /**
     * @var JWTAuthenticatable
     */
    private $user;

    /**
     * Logout constructor.
     *
     * @param JWTAuthenticatable $user
     */
    public function __construct(JWTAuthenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * @return JWTAuthenticatable
     */
    public function getUser(): JWTAuthenticatable
    {
        return $this->user;
    }
}
