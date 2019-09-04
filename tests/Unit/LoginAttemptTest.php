<?php

namespace SPie\LaravelJWT\Test\Unit;

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Events\LoginAttempt;
use SPie\LaravelJWT\Test\TestHelper;

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
        $credentials = [$this->getFaker()->uuid => $this->getFaker()->uuid];
        $ipAddress = $this->getFaker()->ipv4;

        $loginAttempt = new LoginAttempt($credentials, $ipAddress);

        $this->assertEquals($credentials, $loginAttempt->getCredentials());
        $this->assertEquals($ipAddress, $loginAttempt->getIpAddress());
    }

    /**
     * @return void
     */
    public function testConstructWithoutOptionalParameters(): void
    {
        $credentials = [$this->getFaker()->uuid => $this->getFaker()->uuid];

        $this->assertEquals($credentials, (new LoginAttempt($credentials))->getCredentials());
    }
}
