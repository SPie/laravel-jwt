<?php

use Faker\Factory;
use Faker\Generator;

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
    protected function tearDown()
    {
        Mockery::close();

        parent::tearDown();
    }
}
