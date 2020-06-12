<?php

namespace SPie\LaravelJWT\Middleware;

use Illuminate\Contracts\Auth\Guard;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;

/**
 * Trait Authenticated
 *
 * @package SPie\LaravelJWT\Middleware
 */
trait Authenticated
{

    /**
     * @param Guard $guard
     *
     * @return $this
     *
     * @throws NotAuthenticatedException
     */
    protected function checkAuthenticated(Guard $guard): self
    {
        if ($guard->guest()) {
            throw new NotAuthenticatedException();
        }

        return $this;
    }
}
