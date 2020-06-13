<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Interface EventFactory
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface EventFactory
{
    /**
     * @param string          $guardName
     * @param Authenticatable $user
     * @param bool            $remember
     *
     * @return Login
     */
    public function createLoginEvent(string $guardName, Authenticatable $user, bool $remember = false): Login;

    /**
     * @param string          $guardName
     * @param Authenticatable $user
     *
     * @return Logout
     */
    public function createLogoutEvent(string $guardName, Authenticatable $user): Logout;
}
