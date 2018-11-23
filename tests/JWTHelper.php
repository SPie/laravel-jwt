<?php

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;

/**
 * Trait JWTHelper
 */
trait JWTHelper
{

    /**
     * @param array       $payload
     * @param string|null $secret
     *
     * @return Token
     */
    protected function createToken(array $payload = [], string $secret = null): Token
    {
        $signer = $this->getSigner();
        $builder = (new Builder())
            ->setHeader('alg', $signer->getAlgorithmId());

        foreach ($payload as $key => $value) {
            $builder->set($key, $value);
        }

        return $builder
            ->sign($this->getSigner(), $secret ?: $this->getFaker()->uuid)
            ->getToken();
    }

    /**
     * @return Signer
     */
    protected function getSigner(): Signer
    {
        return new Sha256();
    }
}
