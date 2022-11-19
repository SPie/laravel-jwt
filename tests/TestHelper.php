<?php

namespace SPie\LaravelJWT\Test;

use Faker\Factory;
use Faker\Generator;
use Mockery;

trait TestHelper
{
    private Generator $faker;

    protected function getFaker(): Generator
    {
        if (!isset($this->faker)) {
            $this->faker = Factory::create();
        }

        return $this->faker;
    }

    protected function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }
}
