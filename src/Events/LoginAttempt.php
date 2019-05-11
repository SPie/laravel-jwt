<?php

namespace SPie\LaravelJWT\Events;

/**
 * Class LoginAttempt
 *
 * @package SPie\LaravelJWT\Events
 */
final class LoginAttempt implements Event
{

    /**
     * @var array
     */
    private $credentials;

    /**
     * LoginAttempt constructor.
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
