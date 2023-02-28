<?php

namespace SPie\LaravelJWT\Events;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;
use SPie\LaravelJWT\Contracts\EventFactory as EventFactoryContract;

final class EventFactory implements EventFactoryContract
{
    public function createLoginEvent(string $guardName, Authenticatable $user, bool $remember = false): Login
    {
        return new Login($guardName, $user, $remember);
    }

    public function createLogoutEvent(string $guardName, Authenticatable $user): Logout
    {
        return new Logout($guardName, $user);
    }

    public function createAttemptingEvent(string $guardName, array $credentials, bool $remember = false): Attempting
    {
        return new Attempting($guardName, $credentials, $remember);
    }

    public function createFailedEvent(string $guardName, ?Authenticatable $user, array $credentials): Failed
    {
        return new Failed($guardName, $user, $credentials);
    }
}
