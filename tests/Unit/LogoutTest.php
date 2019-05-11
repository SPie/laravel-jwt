<?php

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTAuthenticatable;
use SPie\LaravelJWT\Events\Logout;

/**
 * Class LogoutTest
 */
class LogoutTest extends TestCase
{

    use TestHelper;

    /**
     * @return void
     */
    public function testConstruct(): void
    {
        $user = Mockery::mock(JWTAuthenticatable::class);

        $logoutEvent = new Logout($user);

        $this->assertEquals($user, $logoutEvent->getUser());
    }
}
