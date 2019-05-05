<?php

namespace SPie\LaravelJWT\Contracts;

/**
 * Interface Registrar
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface Registrar
{

    /**
     * @return Registrar
     */
    public function register(): Registrar;

    /**
     * @return Registrar
     */
    public function boot(): Registrar;
}
