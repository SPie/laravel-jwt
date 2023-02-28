<?php

namespace SPie\LaravelJWT\Contracts;

interface TokenBlockList
{
    public function revoke(JWT $jwt): self;

    public function isRevoked(string $jwt): bool;
}
