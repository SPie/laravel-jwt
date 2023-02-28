<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Authenticatable;

interface EventFactory
{
    public function createLoginEvent(string $guardName, Authenticatable $user, bool $remember = false): Login;

    public function createLogoutEvent(string $guardName, Authenticatable $user): Logout;

    public function createAttemptingEvent(string $guardName, array $credentials, bool $remember = false): Attempting;

    public function createFailedEvent(string $guardName, ?Authenticatable $user, array $credentials): Failed;
}
