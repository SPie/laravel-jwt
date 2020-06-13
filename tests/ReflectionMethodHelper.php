<?php

namespace SPie\LaravelJWT\Test;

/**
 * Trait ReflectionMethod
 */
trait ReflectionMethodHelper
{

    /**
     * @param mixed  $object
     * @param string $methodName
     * @param array  $arguments
     *
     * @return mixed
     *
     * @throws \ReflectionException
     */
    protected function runReflectionMethod(
        $object,
        string $methodName,
        array $arguments = []
    ) {
        $reflectionMethod = $this->getReflectionObject($object)->getMethod($methodName);
        $reflectionMethod->setAccessible(true);

        return $reflectionMethod->invokeArgs($object, $arguments);
    }

    /**
     * @param mixed  $object
     * @param string $propertyName
     *
     * @return mixed
     */
    protected function getPrivateProperty($object, string $propertyName)
    {
        return $this->getProperty($object, $propertyName)->getValue($object);
    }

    /**
     * @param mixed  $object
     * @param string $propertyName
     * @param mixed  $value
     *
     * @return $this
     */
    protected function setPrivateProperty($object, string $propertyName, $value)
    {
        $this->getProperty($object, $propertyName)->setValue($object, $value);

        return $this;
    }

    /**
     * @param mixed  $object
     * @param string $propertyName
     *
     * @return ReflectionProperty
     */
    private function getProperty($object, string $propertyName): \ReflectionProperty
    {
        $property = $this->getReflectionObject($object)->getProperty($propertyName);
        $property->setAccessible(true);

        return $property;
    }

    /**
     * @param mixed $object
     *
     * @return ReflectionObject
     */
    private function getReflectionObject($object): \ReflectionObject
    {
        return new \ReflectionObject($object);
    }
}
