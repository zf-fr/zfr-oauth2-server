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
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Repository\AccessTokenRepositoryInterface;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\ScopeService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AccessTokenServiceFactory
{
    /**
     * @param  ContainerInterface $container
     * @return AccessTokenService
     */
    public function __invoke(ContainerInterface $container): AccessTokenService
    {
        /** @var ServerOptions $serverOptions */
        $serverOptions = $container->get(ServerOptions::class);

        /** @var AccessTokenRepositoryInterface $tokenRepository */
        $tokenRepository = $container->get(AccessTokenRepositoryInterface::class);

        /* @var ScopeService $scopeService */
        $scopeService = $container->get(ScopeService::class);

        return new AccessTokenService($tokenRepository, $scopeService, $serverOptions);
    }
}
