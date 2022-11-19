<?php

namespace SPie\LaravelJWT\Contracts;

interface Registrar
{
    public function register(): Registrar;

    public function boot(): Registrar;
}
