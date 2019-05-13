<?php

namespace SPie\LaravelJWT\Test;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Trait HttpHelper
 */
trait HttpHelper
{

    /**
     * @return Request
     */
    private function createEmptyRequest(): Request
    {
        return new Request();
    }

    /**
     * @return Response
     */
    private function createEmptyResponse(): Response
    {
        return new Response();
    }
}
