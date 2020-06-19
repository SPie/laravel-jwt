<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Events\EventFactory;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\TestHelper;

/**
 * Class EventFactoryTest
 *
 * @package SPie\LaravelJWT\Test\Unit
 */
final class EventFactoryTest extends TestCase
{
    use TestHelper;
    use JWTHelper;

    //region Tests

    /**
     * @return void
     */
    public function testCreateLoginEvent(): void
    {
        $guardName = $this->getFaker()->word;
        $user = $this->createAuthenticatable();
        $remember = $this->getFaker()->boolean;

        $this->assertEquals(
            new Login($guardName, $user, $remember),
            $this->getEventFactory()->createLoginEvent($guardName, $user, $remember)
        );
    }

    /**
     * @return void
     */
    public function testCreateLogoutEvent(): void
    {
        $guardName = $this->getFaker()->word;
        $user = $this->createAuthenticatable();

        $this->assertEquals(
            new Logout($guardName, $user),
            $this->getEventFactory()->createLogoutEvent($guardName, $user)
        );
    }

    /**
     * @return void
     */
    public function testCreateAttemptingEvent(): void
    {
        $guardName = $this->getFaker()->word;
        $credentials = [$this->getFaker()->word => $this->getFaker()->word];
        $remember = $this->getFaker()->boolean;

        $this->assertEquals(
            new Attempting($guardName, $credentials, $remember),
            $this->getEventFactory()->createAttemptingEvent($guardName, $credentials, $remember)
        );
    }

    /**
     * @return void
     */
    public function testCreateFailedEvent(): void
    {
        $guardName = $this->getFaker()->word;
        $user = $this->createAuthenticatable();
        $credentials = [$this->getFaker()->word => $this->getFaker()->word];

        $this->assertEquals(
            new Failed($guardName, $user, $credentials),
            $this->getEventFactory()->createFailedEvent($guardName, $user, $credentials)
        );
    }

    //endregion

    /**
     * @return EventFactory
     */
    private function getEventFactory(): EventFactory
    {
        return new EventFactory();
    }
}
