<?php

namespace SPie\LaravelJWT\Events;

/**
 * Class FailedLoginAttempt
 *
 * @package SPie\LaravelJWT\Events
 */
final class FailedLoginAttempt implements Event, IpAddressable
{
    use IpAddress;

    /**
     * @var array
     */
    private $credentials;

    /**
     * FailedLoginAttempt constructor.
     *
     * @param array       $credentials
     * @param string|null $ipAddress
     */
    public function __construct(array $credentials, string $ipAddress = null)
    {
        $this->credentials = $credentials;
        $this->ipAddress = $ipAddress;
    }

    /**
     * @return array
     */
    public function getCredentials(): array
    {
        return $this->credentials;
    }
}
