<?php

namespace SPie\LaravelJWT\Events;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use SPie\LaravelJWT\Contracts\EventFactory as EventFactoryContract;

/**
 * Class EventFactory
 *
 * @package SPie\LaravelJWT\Events
 */
final class EventFactory implements EventFactoryContract
{
    /**
     * @param string          $guardName
     * @param Authenticatable $user
     * @param bool            $remember
     *
     * @return Login
     */
    public function createLoginEvent(string $guardName, Authenticatable $user, bool $remember = false): Login
    {
        return new Login($guardName, $user, $remember);
    }

    /**
     * @param string          $guardName
     * @param Authenticatable $user
     *
     * @return Logout
     */
    public function createLogoutEvent(string $guardName, Authenticatable $user): Logout
    {
        return new Logout($guardName, $user);
    }

    /**
     * @param string $guardName
     * @param array  $credentials
     * @param bool   $remember
     *
     * @return Attempting
     */
    public function createAttemptingEvent(string $guardName, array $credentials, bool $remember = false): Attempting
    {
        return new Attempting($guardName, $credentials, $remember);
    }

    /**
     * @param string               $guardName
     * @param Authenticatable|null $user
     * @param array                $credentials
     *
     * @return Failed
     */
    public function createFailedEvent(string $guardName, ?Authenticatable $user, array $credentials): Failed
    {
        return new Failed($guardName, $user, $credentials);
    }
}
