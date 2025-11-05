<?php

namespace SPie\LaravelJWT\Providers;

use Illuminate\Contracts\Container\Container;
use SPie\LaravelJWT\Contracts\Registrar as RegistrarContract;

trait RegistrarHolder
{
    private RegistrarContract $registrar;

    private function createRegistrar(Container $app): RegistrarContract
    {
        return new Registrar($app);
    }
}
