<?php

namespace SPie\LaravelJWT\Test;

use Illuminate\Http\Request;
use Mockery as m;
use Mockery\MockInterface;

trait RequestHelper
{
    /**
     * @return Request|MockInterface
     */
    private function createRequest(): Request
    {
        return m::spy(Request::class);
    }

    private function mockRequestIp(MockInterface $request, ?string $ipAddress)
    {
        $request
            ->shouldReceive('ip')
            ->andReturn($ipAddress);

        return $this;
    }
}
