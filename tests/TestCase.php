<?php

use Faker\Factory;
use Faker\Generator;
use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * Class TestCase
 */
class TestCase extends BaseTestCase
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
