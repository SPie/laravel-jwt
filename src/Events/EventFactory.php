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
        // TODO: Implement createLoginEvent() method.
    }

    public function createLogoutEvent(string $guardName, Authenticatable $user): Logout
    {
        // TODO: Implement createLogoutEvent() method.
    }

    public function createAttemptingEvent(string $guardName, array $credentials, bool $remember = false): Attempting
    {
        // TODO: Implement createAttemptingEvent() method.
    }

    public function createFailedEvent(string $guardName, ?Authenticatable $user, array $credentials): Failed
    {
        // TODO: Implement createFailedEvent() method.
    }
}
