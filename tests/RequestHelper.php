<?php

namespace SPie\LaravelJWT\Test;

use Illuminate\Http\Request;
use Mockery as m;
use Mockery\MockInterface;

/**
 * Trait RequestHelper
 *
 * @package SPie\LaravelJWT\Test
 */
trait RequestHelper
{
    //region Mocks

    /**
     * @return Request|MockInterface
     */
    private function createRequest(): Request
    {
        return m::mock(Request::class)
            ->shouldAllowMockingProtectedMethods()
            ->makePartial();
    }

    /**
     * @param Request|MockInterface $request
     * @param string|null           $ipAddress
     *
     * @return $this
     */
    private function mockRequestIp(MockInterface $request, ?string $ipAddress)
    {
        $request
            ->shouldReceive('ip')
            ->andReturn($ipAddress);

        return $this;
    }

    //endregion
}
