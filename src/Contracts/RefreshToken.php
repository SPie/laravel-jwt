<?php

namespace SPie\LaravelJWT\Contracts;

interface RefreshToken
{
    public function getCode(): string;

    public function getToken(): string;

    public function getDisabledAt(): ?\DateTimeImmutable;
}
