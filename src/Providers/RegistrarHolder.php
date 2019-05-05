<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Foundation\Application;
use SPie\LaravelJWT\Contracts\Registrar as RegistrarContract;

/**
 * Trait RegistrarHolder
 *
 * @package SPie\LaravelJWT\Providers
 */
trait RegistrarHolder
{

    /**
     * @var RegistrarContract
     */
    protected $registrar;

    /**
     * @param Application $app
     *
     * @return RegistrarContract
     */
    protected function createRegistrar(Application $app): RegistrarContract
    {
        return new Registrar($app);
    }

    /**
     * @return RegistrarContract
     */
    protected function getRegistrar(): RegistrarContract
    {
        return $this->registrar;
    }
}
