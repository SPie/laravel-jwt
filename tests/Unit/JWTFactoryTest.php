<?php

namespace SPie\LaravelJWT\Test\Unit;

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTFactory;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\TestHelper;

/**
 * Class JWTFactoryTest
 */
class JWTFactoryTest extends TestCase
{
    use TestHelper;
    use JWTHelper;

    //region Tests

    /**
     * @return void
     */
    public function testCreateJWT(): void
    {
        $token = $this->createToken();
        $jwtFactory = new JWTFactory();

        $this->assertEquals(new JWT($token), $jwtFactory->createJWT($token));
    }

    //endregion
}
