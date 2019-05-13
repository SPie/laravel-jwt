<?php

namespace SPie\LaravelJWT\Test\Unit;

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Events\FailedLoginAttempt;
use SPie\LaravelJWT\Test\TestHelper;

/**
 * Class FailedLoginAttemptTest
 */
final class FailedLoginAttemptTest extends TestCase
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

        $this->assertEquals($credentials, (new FailedLoginAttempt($credentials))->getCredentials());
    }
}
