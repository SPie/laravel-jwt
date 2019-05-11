<?php

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Events\LoginAttempt;

/**
 * Class LoginAttemptTest
 */
final class LoginAttemptTest extends TestCase
{

    use TestHelper;

    /**
     * @return void
     */
    public function testConstruct(): void
    {
        $credentials = [
            $this->getFaker()->uuid => $this->getFaker()->uuid,
        ];

        $this->assertEquals($credentials, (new LoginAttempt($credentials))->getCredentials());
    }
}
