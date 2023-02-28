<?php

namespace SPie\LaravelJWT\Test;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

trait HttpHelper
{
    private function createEmptyRequest(): Request
    {
        return new Request();
    }

    private function createEmptyResponse(): Response
    {
        return new Response();
    }
}
