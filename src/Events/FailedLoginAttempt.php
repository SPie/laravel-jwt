<?php

namespace SPie\LaravelJWT\Events;

/**
 * Class FailedLoginAttempt
 *
 * @package SPie\LaravelJWT\Events
 */
final class FailedLoginAttempt implements Event
{

    /**
     * @var array
     */
    private $credentials;

    /**
     * FailedLoginAttempt constructor.
     *
     * @param array $credentials
     */
    public function __construct(array $credentials)
    {
        $this->credentials = $credentials;
    }

    /**
     * @return array
     */
    public function getCredentials(): array
    {
        return $this->credentials;
    }
}
