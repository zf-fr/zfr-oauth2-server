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
use ZfrOAuth2\Server\Container\RefreshTokenServiceFactory;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Repository\RefreshTokenRepositoryInterface;
use ZfrOAuth2\Server\Service\RefreshTokenService;
use ZfrOAuth2\Server\Service\ScopeService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Container\RefreshTokenServiceFactory
 */
class RefreshTokenServiceFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCreateFromFactory()
    {
        $container = $this->createMock(ContainerInterface::class);

        $serverOptions = ServerOptions::fromArray();

        $container->expects($this->at(0))
            ->method('get')
            ->with(ServerOptions::class)
            ->willReturn($serverOptions);

        $container->expects($this->at(1))
            ->method('get')
            ->with(RefreshTokenRepositoryInterface::class)
            ->willReturn($this->createMock(RefreshTokenRepositoryInterface::class));

        $container->expects($this->at(2))
            ->method('get')
            ->with(ScopeService::class)
            ->willReturn($this->createMock(ScopeService::class));

        $factory = new RefreshTokenServiceFactory();
        $service = $factory($container);

        $this->assertInstanceOf(RefreshTokenService::class, $service);
    }
}
