<?php

namespace SPie\LaravelJWT\Contracts;

interface JWTHandler
{
    public function getValidJWT(string $token): JWT;

    public function createJWT(string $subject, array $payload = [], ?int $ttl = null): JWT;
}
