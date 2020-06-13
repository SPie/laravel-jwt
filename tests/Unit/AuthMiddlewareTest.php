<?php

namespace SPie\LaravelJWT\Test\Unit;

use Illuminate\Contracts\Auth\Factory;
use Illuminate\Contracts\Auth\Guard;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTGuard;
use SPie\LaravelJWT\Exceptions\NotAuthenticatedException;
use SPie\LaravelJWT\Middleware\AuthMiddleware;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\TestHelper;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class AuthMiddlewareTest
 */
final class AuthMiddlewareTest extends TestCase
{
    use JWTHelper;
    use TestHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws NotAuthenticatedException
     */
    public function testHandle(): void
    {
        $request = new Request();
        $responseHeader = $this->getFaker()->uuid;
        $guardIdentifier = $this->getFaker()->uuid;
        $authFactory = $this->createAuthFactory($this->createGuard(false));

        $response = $this->createAuthMiddleware($authFactory)->handle(
            $request,
            function (Request $handledRequest) use ($request, $responseHeader) {
                $response = new Response();
                $response->headers->set('Test', $responseHeader);

                return $response;
            },
            $guardIdentifier
        );

        $this->assertEquals($responseHeader, $response->headers->get('Test'));

        $authFactory
            ->shouldHaveReceived('guard')
            ->with($guardIdentifier)
            ->once();
    }

    /**
     * @return void
     *
     * @throws NotAuthenticatedException
     */
    public function testHandleWithError(): void
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->createAuthMiddleware($this->createAuthFactory($this->createGuard(true)))
             ->handle(new Request(), function () {
             });
    }

    //endregion

    //region Mocks

    /**
     * @param Factory $authFactory
     *
     * @return AuthMiddleware
     */
    private function createAuthMiddleware(Factory $authFactory): AuthMiddleware
    {
        return new AuthMiddleware($authFactory);
    }

    /**
     * @param Guard $jwtGuard
     *
     * @return Factory|MockInterface
     */
    private function createAuthFactory(Guard $jwtGuard): Factory
    {
        $authFactory = Mockery::spy(Factory::class);
        $authFactory
            ->shouldReceive('guard')
            ->andReturn($jwtGuard);

        return $authFactory;
    }

    /**
     * @param bool $isGuest
     *
     * @return JWTGuard
     */
    private function createGuard(bool $isGuest = false): JWTGuard
    {
        $jwtGuard = $this->createJWTGuard();
        $this->addGuest($jwtGuard, $isGuest);

        return $jwtGuard;
    }

    /**
     * @param Guard|MockInterface $jwtGuard
     * @param bool                $isGuest
     *
     * @return AuthMiddlewareTest
     */
    private function addGuest(Guard $jwtGuard, bool $isGuest): AuthMiddlewareTest
    {
        $jwtGuard
            ->shouldReceive('guest')
            ->andReturn($isGuest);

        return $this;
    }

    //endregion
}
