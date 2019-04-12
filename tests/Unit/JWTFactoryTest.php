<?php

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\JWT;
use SPie\LaravelJWT\JWTFactory;

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
