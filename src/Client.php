<?php

declare(strict_types=1);

namespace Akamai\Open\EdgeGrid;

use Akamai\Open\EdgeGrid\Authentication;
use Akamai\Open\EdgeGrid\Authentication\Nonce;
use Akamai\Open\EdgeGrid\Authentication\Timestamp;
use Akamai\Open\EdgeGrid\Handler\Authentication as AuthenticationHandler;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\ClientTrait;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class Client implements ClientInterface
{
    use ClientTrait;

    private const VERSION = '1.0.0';
    private const DEFAULT_REQUEST_TIMEOUT = 300;

    private Authentication $authentication;

    private readonly GuzzleClient $guzzleClient;

    /** @param array<string, mixed> $config */
    public function __construct(
        array $config = [],
        ?Authentication $authentication = null
    ) {
        $config = $this->addAuthenticationToConfig($config, $authentication);
        $config = $this->addBasicOptionsToConfig($config);
        $config['headers'] ??= [];
        \assert(\is_array($config['headers']), "Headers must be an array");
        $config['headers']['User-Agent'] = 'Akamai-Open-Edgegrid-PHP/' .
            self::VERSION . ' ' . Utils::defaultUserAgent();

        $this->guzzleClient = new GuzzleClient($config);
    }

    /**
     * @inheritDoc
     *
     * @param array<string, mixed> $options
     */
    public function requestAsync(string $method, $uri = '', array $options = []): PromiseInterface
    {
        $options = $this->addRequestOptionsToOptions($options);

        $query = \parse_url((string) $uri, \PHP_URL_QUERY);

        if (!empty($query)) {
            $uri = \mb_substr((string) $uri, 0, (\mb_strlen($query) + 1) * -1);
            \parse_str($query, $options['query']);
        }

        return $this->guzzleClient->requestAsync($method, $uri, $options);
    }

    /**
     * @inheritDoc
     *
     * @param array<string, mixed> $options
     */
    public function request(string $method, $uri, array $options = []): ResponseInterface
    {
        $options = $this->addRequestOptionsToOptions($options);
        return $this->guzzleClient->request($method, $uri, $options);
    }

    /** @param array<string, mixed> $options */
    public function send(RequestInterface $request, array $options = []): ResponseInterface
    {
        return $this->guzzleClient->send($request, $options);
    }

    /** @return array<string, mixed> */
    public function getConfig(?string $option = null): array
    {
        /** @var array<string, mixed> $config */
        $config = $this->guzzleClient->getConfig($option);

        return $config;
    }

    /**
     * @inheritDoc
     *
     * @param array<string, mixed> $options
     */
    public function sendAsync(RequestInterface $request, array $options = []): PromiseInterface
    {
        $options = $this->addRequestOptionsToOptions($options);

        return $this->guzzleClient->sendAsync($request, $options);
    }

    /** @param array<string, mixed> $config */
    private function setAuthentication(array $config, ?Authentication $authentication = null): void
    {
        $this->authentication = $authentication ?? new Authentication();

        $timestamp = $config['timestamp'] ?? null;

        if ($timestamp) {
            \assert(\is_string($timestamp) || $timestamp instanceof Timestamp);
            $this->authentication->setTimestamp($timestamp);
        }

        $nonce = $config['nonce'] ?? null;

        // phpcs:disable SlevomatCodingStandard.ControlStructures.EarlyExit.EarlyExitNotUsed
        if ($nonce) {
            // phpcs:enable
            \assert(\is_string($nonce) || $nonce instanceof Nonce);
            $this->authentication->setNonce($nonce);
        }
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function addAuthenticationToConfig(array $config, ?Authentication $authentication = null): array
    {
        $this->setAuthentication($config, $authentication);

        $authenticationHandler = new AuthenticationHandler();
        $authenticationHandler->setSigner($this->authentication);

        $config['handler'] ??= HandlerStack::create();

        try {
            if (!($config['handler'] instanceof HandlerStack)) {
                \assert(
                    \is_callable($config['handler']),
                    "Callable handler expected, got " . \gettype($config['handler'])
                );
                $config['handler'] = HandlerStack::create($config['handler']);
            }

            $config['handler']->before('history', $authenticationHandler, 'authentication');
        } catch (\InvalidArgumentException) {
            \assert(
                $config['handler'] instanceof HandlerStack,
                "HandlerStack expected, got " . \gettype($config['handler'])
            );
            // history middleware not added yet
            $config['handler']->push($authenticationHandler, 'authentication');
        }

        return $config;
    }

    /**
     * Set timeout and base_uri options
     *
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function addBasicOptionsToConfig(array $config): array
    {
        $config['timeout'] ??= self::DEFAULT_REQUEST_TIMEOUT;

        $baseUri = $config['base_uri'] ?? null;

        if (\is_string($baseUri) && $baseUri && !\str_contains($baseUri, 'http')) {
            $baseUri = 'https://' . $baseUri;

            return $config;
        }

        return $config;
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>
     */
    private function addRequestOptionsToOptions(array $options): array
    {
        $this->authentication->setTimestamp();
        $nonce = $options['nonce'] ?? null;

        if ($nonce) {
            \assert(\is_string($nonce) || $nonce instanceof Nonce, "Nonce must be a string or instance of Nonce");
            $this->authentication->setNonce($nonce);
        }

        if (isset($options['handler'])) {
            $options = $this->addAuthenticationToConfig($options, $this->authentication);
        }

        return $options;
    }
}
