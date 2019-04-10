<?php

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
     * @throws ReflectionException
     */
    protected function runReflectionMethod(
        $object,
        string $methodName,
        array $arguments = []
    )
    {
        $reflectionObject = new \ReflectionObject($object);
        $reflectionMethod = $reflectionObject->getMethod($methodName);
        $reflectionMethod->setAccessible(true);

        return $reflectionMethod->invokeArgs($object, $arguments);
    }
}
