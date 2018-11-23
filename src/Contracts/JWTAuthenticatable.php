<?php

namespace SPie\LaravelJWT\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Interface JWTAuthenticatable
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface JWTAuthenticatable extends Authenticatable {

    /**
     * @return array
     */
    public function getCustomClaims(): array;
}