<?php

namespace SPie\LaravelJWT\Contracts;

/**
 * Interface JWTHandler
 *
 * @package SPie\LaravelJWT\Contracts
 */
interface JWTHandler
{
    /**
     * @param string $token
     *
     * @return JWT
     */
    public function getValidJWT(string $token): JWT;

    /**
     * @param string   $subject
     * @param array    $payload
     * @param int|null $ttl
     *
     * @return JWT
     */
    public function createJWT(string $subject, array $payload = [], int $ttl = null): JWT;
}
