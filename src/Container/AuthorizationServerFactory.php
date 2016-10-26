<?php

declare(strict_types = 1);

/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

namespace ZfrOAuth2\Server\Container;

use Interop\Container\ContainerInterface;
use ZfrOAuth2\Server\AuthorizationServer;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\ClientService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AuthorizationServerFactory
{
    /**
     * @param  ContainerInterface $container
     * @return AuthorizationServer
     */
    public function __invoke(ContainerInterface $container): AuthorizationServer
    {
        /* @var ClientService $clientService */
        $clientService = $container->get(ClientService::class);

        /* @var ServerOptions $serverOptions */
        $serverOptions = $container->get(ServerOptions::class);

        $grants = [];
        foreach ($serverOptions->getGrants() as $grant) {
            $grants[] = $container->get($grant);
        }

        /** @var AccessTokenService $accessTokenService */
        $accessTokenService = $container->get(AccessTokenService::class);

        /** @var RefreshTokenService $refreshTokenService */
        $refreshTokenService = $container->get(RefreshTokenService::class);

        return new AuthorizationServer($clientService, $grants, $accessTokenService, $refreshTokenService);
    }
}
