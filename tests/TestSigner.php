<?php

namespace SPie\LaravelJWT\Test;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

class TestSigner implements Signer
{
    public function sign(string $payload, Key $key): string
    {
    }

    public function verify(string $expected, string $payload, Key $key): bool
    {
    }

    public function algorithmId(): string
    {
    }
}
