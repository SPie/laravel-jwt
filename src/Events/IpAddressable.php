<?php

namespace SPie\LaravelJWT\Events;

/**
 * Interface IpAddressable
 *
 * @package SPie\LaravelJWT\Events
 */
interface IpAddressable
{
    /**
     * @return string|null
     */
    public function getIpAddress(): ?string;
}
