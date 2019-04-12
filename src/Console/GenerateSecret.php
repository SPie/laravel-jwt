<?php

namespace SPie\LaravelJWT\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Filesystem\FileNotFoundException;
use Illuminate\Support\Str;

/**
 * Class GenerateSecret
 *
 * @package SPie\LaravelJWT\Console
 */
final class GenerateSecret extends Command
{

    const COMMAND      = 'jwt:generate:secret';
    const OPTION_FORCE = 'force';

    const CONFIG_JWT_SECRET = 'JWT_SECRET';

    /**
     * @var string
     */
    protected $signature = self::COMMAND . ' {--f|' . self::OPTION_FORCE . ' : Force replacement without confirmation.}';

    /**
     * @return void
     */
    public function handle(): void
    {
        $secret = Str::random(32);

        if (!\file_exists($this->getEnvPath())) {
            $this->showSecret($secret);
            return;
        }

        if ($this->secretExists()) {
            if (!$this->replaceConfirmed()) {
                $this->info('Generating secret canceled.');

                return;
            }

            $this->replaceSecret($secret);
        } else {
            $this->writeSecret($secret);
        }

        $this->showSecret($secret);
    }

    /**
     * @param string $secret
     *
     * @return GenerateSecret
     */
    protected function showSecret(string $secret): GenerateSecret
    {
        $this->info('The secret is: ' . $secret);

        return $this;
    }

    /**
     * @return bool
     */
    protected function secretExists(): bool
    {
        return Str::contains($this->getEnvFileContents(), self::CONFIG_JWT_SECRET);
    }

    /**
     * @return bool
     */
    protected function replaceConfirmed(): bool
    {
        if ($this->isForced()) {
            return true;
        }

        return $this->confirm('Do you really want to replace the existing secret?');
    }

    /**
     * @param string $secret
     *
     * @return GenerateSecret
     */
    protected function replaceSecret(string $secret): GenerateSecret
    {
        return $this->writeToFile(
            Str::replaceFirst(
                $this->createConfigString($this->laravel['config']['jwt.secret']),
                $this->createConfigString($secret),
                $this->getEnvFileContents()
            ),
            false
        );
    }

    /**
     * @param string $secret
     *
     * @return GenerateSecret
     */
    protected function writeSecret(string $secret): GenerateSecret
    {
        return $this->writeToFile($this->createConfigString($secret));
    }

    /**
     * @return string
     *
     * @throws FileNotFoundException
     */
    protected function getEnvFileContents(): string
    {
        $content = \file_get_contents($this->getEnvPath());

        if ($content === false) {
            throw new FileNotFoundException($this->getEnvPath());
        }

        return $content;
    }

    /**
     * @param string $input
     * @param bool   $append
     *
     * @return GenerateSecret
     */
    protected function writeToFile(string $input, bool $append = true): GenerateSecret
    {
        \file_put_contents($this->getEnvPath(), $input, $append ? FILE_APPEND : null);

        return $this;
    }

    /**
     * @param string $secret
     *
     * @return string
     */
    protected function createConfigString(string $secret): string
    {
        return self::CONFIG_JWT_SECRET . '=' . $secret;
    }

    /**
     * @return string
     */
    protected function getEnvPath(): string
    {
        return $this->getLaravel()->basePath() . '/.env';
    }

    /**
     * @return bool
     */
    protected function isForced(): bool
    {
        return !empty($this->option(self::OPTION_FORCE));
    }
}
