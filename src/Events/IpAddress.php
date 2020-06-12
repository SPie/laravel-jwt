<?php

namespace SPie\LaravelJWT\Events;

/**
 * Trait IpAddress
 *
 * @package SPie\LaravelJWT\Events
 */
trait IpAddress
{
    /**
     * @var string|null
     */
    private ?string $ipAddress;

    /**
     * @return string|null
     */
    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }
}
