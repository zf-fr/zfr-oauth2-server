<?php

declare(strict_types=1);

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

namespace ZfrOAuth2Test\Server\Container;

use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use ZfrOAuth2\Server\AuthorizationServer;
use ZfrOAuth2\Server\Container\AuthorizationServerFactory;
use ZfrOAuth2\Server\Grant\GrantInterface;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\ClientService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Container\AuthorizationServerFactory
 */
class AuthorizationServerFactoryTest extends TestCase
{
    public function testCanCreateFromFactory(): void
    {
        $container     = $this->createMock(ContainerInterface::class);
        $serverOptions = ServerOptions::fromArray(['grants' => ['MyGrant']]);

        $container
            ->expects($this->exactly(5))
            ->method('get')
            ->withConsecutive([ClientService::class], [ServerOptions::class], ['MyGrant'], [AccessTokenService::class], [RefreshTokenService::class])
            ->will(
                $this->onConsecutiveCalls(
                    $this->createMock(ClientService::class),
                    $serverOptions,
                    $this->createMock(GrantInterface::class),
                    $this->createMock(AccessTokenService::class),
                    $this->createMock(RefreshTokenService::class),
                )
            );

        $factory = new AuthorizationServerFactory();
        $service = $factory($container);

        $this->assertInstanceOf(AuthorizationServer::class, $service);
    }
}
