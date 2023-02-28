<?php

namespace SPie\LaravelJWT\Test;

trait ReflectionMethodHelper
{

    /**
     * @return mixed
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
     * @return mixed
     */
    protected function getPrivateProperty($object, string $propertyName)
    {
        return $this->getProperty($object, $propertyName)->getValue($object);
    }

    protected function setPrivateProperty($object, string $propertyName, $value): self
    {
        $this->getProperty($object, $propertyName)->setValue($object, $value);

        return $this;
    }

    private function getProperty($object, string $propertyName): \ReflectionProperty
    {
        $property = $this->getReflectionObject($object)->getProperty($propertyName);
        $property->setAccessible(true);

        return $property;
    }

    private function getReflectionObject($object): \ReflectionObject
    {
        return new \ReflectionObject($object);
    }
}
