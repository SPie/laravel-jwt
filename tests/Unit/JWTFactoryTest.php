<?php

namespace SPie\LaravelJWT\Test\Unit;

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTFactory;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\TestHelper;

class JWTFactoryTest extends TestCase
{
    use TestHelper;
    use JWTHelper;

    public function testCreateJWT(): void
    {
        $token = $this->createToken();
        $jwtFactory = new JWTFactory();

        $this->assertEquals(new JWT($token), $jwtFactory->createJWT($token));
    }
}
