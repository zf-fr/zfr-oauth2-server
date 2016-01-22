<?php
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

use Interop\Container\ContainerInterface;
use ZfrOAuth2\Server\AuthorizationServer;
use ZfrOAuth2\Server\Container\AuthorizationServerFactory;
use ZfrOAuth2\Server\Grant\GrantInterface;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Service\ClientService;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 *
 * @covers  ZfrOAuth2\Server\Container\AuthorizationServerFactory
 */
class AuthorizationServerFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCreateFromFactory()
    {
        $container     = $this->getMock(ContainerInterface::class);
        $serverOptions = new ServerOptions(['grants' => ['MyGrant']]);

        $container->expects($this->at(0))
            ->method('get')
            ->with(ClientService::class)
            ->willReturn($this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false));

        $container->expects($this->at(1))
            ->method('get')
            ->with(ServerOptions::class)
            ->willReturn($serverOptions);

        $container->expects($this->at(2))
            ->method('get')
            ->with('MyGrant')
            ->willReturn($this->getMock(GrantInterface::class, [], [], '', false));

        $container->expects($this->at(3))
            ->method('get')
            ->with(TokenService::AccessTokenService)
            ->willReturn($this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false));

        $container->expects($this->at(4))
            ->method('get')
            ->with('ZfrOAuth2\Server\Service\RefreshTokenService')
            ->willReturn($this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false));

        $factory = new AuthorizationServerFactory();
        $service = $factory($container);

        $this->assertInstanceOf(AuthorizationServer::class, $service);
    }
}
