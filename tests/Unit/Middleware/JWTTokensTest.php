<?php

namespace SPie\LaravelJWT\Test\Unit\Middleware;

use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Contracts\JWTGuard;
use SPie\LaravelJWT\Middleware\JWTTokens;
use SPie\LaravelJWT\Test\HttpHelper;
use SPie\LaravelJWT\Test\JWTHelper;
use SPie\LaravelJWT\Test\RequestHelper;
use Symfony\Component\HttpFoundation\Request;

final class JWTTokensTest extends TestCase
{
    use HttpHelper;
    use JWTHelper;
    use RequestHelper;

    private function getJWTTokens(JWTGuard $jwtGuard = null): JWTTokens
    {
        return new JWTTokens($jwtGuard ?: $this->createJWTGuard());
    }

    private function setUpHandleTest(): array
    {
        $request = $this->createRequest();
        $response = $this->createEmptyResponse();
        $next = fn (Request $request) => $response;
        $jwtGuard = $this->createJWTGuard();
        $this->mockJWTGuardReturnTokens($jwtGuard, $response);
        $jwtTokens = $this->getJWTTokens($jwtGuard);
    
        return [$jwtTokens, $request, $next, $response, $jwtGuard];
    }

    public function testHandle(): void
    {
        /**
         * @var JWTTokens $jwtTokens
         * @var JWTGuard  $jwtGuard
         */
        [$jwtTokens, $request, $next, $response, $jwtGuard] = $this->setUpHandleTest();

        $this->assertEquals($response, $jwtTokens->handle($request, $next));
        $this->assertJWTGuardReturnTokens($jwtGuard, $response);
    }
}
