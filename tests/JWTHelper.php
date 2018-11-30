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
     * @param int         $ttl
     *
     * @return Token
     *
     * @throws Exception
     */
    protected function createToken(array $payload = [], string $secret = null, int $ttl = 0): Token
    {
        $signer = $this->getSigner();
        $builder = (new Builder())
            ->setHeader('alg', $signer->getAlgorithmId());

        foreach ($payload as $key => $value) {
            $builder->set($key, $value);
        }

        if ($ttl !== 0) {
            $expiration = ($ttl > 0)
                ? (new \DateTimeImmutable())->add(new \DateInterval('PT' . $ttl . 'M'))
                : (new \DateTimeImmutable())->sub(new \DateInterval('PT' . (-1 * $ttl) . 'M'));

            $builder->setExpiration($expiration->getTimestamp());
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
