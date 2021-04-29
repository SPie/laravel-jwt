<?php

namespace SPie\LaravelJWT\Test;

use Faker\Factory;
use Faker\Generator;
use Mockery;

/**
 * Trait TestCase
 */
trait TestHelper
{

    /**
     * @var Generator
     */
    private $faker;

    /**
     * @return Generator
     */
    protected function getFaker(): Generator
    {
        if (!isset($this->faker)) {
            $this->faker = Factory::create();
        }

        return $this->faker;
    }

    /**
     * @return void
     */
    protected function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }
}
