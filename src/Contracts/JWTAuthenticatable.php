<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface JWTAuthenticatable extends Authenticatable
{
    public function getCustomClaims(): array;
}
