<?php

use Illuminate\Cache\Repository;
use Mockery\MockInterface;
use PHPUnit\Framework\TestCase;
use SPie\LaravelJWT\Blacklist\CacheTokenBlacklist;
use SPie\LaravelJWT\Contracts\JWT;

/**
 * Class CacheTokenBlacklistTest
 */
final class CacheTokenBlacklistTest extends TestCase
{

    use TestHelper;
    use JWTHelper;

    //region Tests

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testRevoke(): void
    {
        $repository = $this->createRepository();
        $jwt = $this->createJWTToRevoke(10);

        $this->assertInstanceOf(
            CacheTokenBlacklist::class,
            $this->createCacheTokenBlacklist($repository)->revoke($jwt)
        );

        $repository
            ->shouldHaveReceived('put')
            ->with(
                $this->hashJWT($jwt->getJWT()),
                $jwt->getJWT(),
                Mockery::on(function ($argument) {
                    return $argument <= 600 && $argument >595;
                })
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testRevokeForever(): void
    {
        $repository = $this->createRepository();
        $jwt = $this->createJWTToRevoke();


        $this->assertInstanceOf(
            CacheTokenBlacklist::class,
            $this->createCacheTokenBlacklist($repository)->revoke($jwt)
        );

        $repository
            ->shouldHaveReceived('forever')
            ->with(
                $this->hashJWT($jwt->getJWT()),
                $jwt->getJWT()
            )
            ->once();
    }

    /**
     * @return void
     *
     * @throws Exception
     */
    public function testIsRevoked(): void
    {
        $jwt = $this->createJWTToRevoke();
        $repository = $this->createRepository();
        $repository
            ->shouldReceive('has')
            ->andReturn(true);

        $this->assertTrue($this->createCacheTokenBlacklist($repository)->isRevoked((string)$jwt->getJWT()));
        $repository
            ->shouldHaveReceived('has')
            ->with($this->hashJWT($jwt->getJWT()))
            ->once();
    }

    /**
     * @return void
     */
    public function testIsRevokedWithoutToken(): void
    {
        $repository = $this->createRepository();
        $repository
            ->shouldReceive('has')
            ->andReturn(false);

        $this->assertFalse($this->createCacheTokenBlacklist($repository)->isRevoked($this->getFaker()->uuid));
    }

    //endregion

    /**
     * @param Repository|null $repository
     *
     * @return CacheTokenBlacklist
     */
    private function createCacheTokenBlacklist(Repository $repository = null): CacheTokenBlacklist
    {
        return new CacheTokenBlacklist($repository ?: $this->createRepository());
    }

    /**
     * @return Repository|MockInterface
     */
    private function createRepository(): Repository
    {
        return Mockery::spy(Repository::class);
    }

    /**
     * @param string $jwt
     *
     * @return string
     */
    private function hashJWT(string $jwt): string
    {
        return \md5($jwt);
    }

    /**
     * @param int|null $ttl
     *
     * @return JWT|MockInterface
     *
     * @throws \Exception
     */
    private function createJWTToRevoke(int $ttl = null): JWT
    {
        return $this->createJWT()
            ->shouldReceive('getJWT')
            ->andReturn($this->getFaker()->uuid)
            ->getMock()
            ->shouldReceive('getExpiresAt')
            ->andReturn(
                $ttl
                    ? (new \DateTimeImmutable())->add(new \DateInterval('PT' . $ttl . 'M'))
                    : null
            )
            ->getMock();
    }
}
