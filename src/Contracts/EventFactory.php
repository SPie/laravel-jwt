<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
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

    /**
     * @param string $guardName
     * @param array  $credentials
     * @param bool   $remember
     *
     * @return Attempting
     */
    public function createAttemptingEvent(string $guardName, array $credentials, bool $remember = false): Attempting;

    /**
     * @param string               $guardName
     * @param Authenticatable|null $user
     * @param array                $credentials
     *
     * @return Failed
     */
    public function createFailedEvent(string $guardName, ?Authenticatable $user, array $credentials): Failed;
}
