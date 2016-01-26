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

use Doctrine\Common\Persistence\ManagerRegistry;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use Interop\Container\ContainerInterface;
use ZfrOAuth2\Server\Container\ClientServiceFactory;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Service\ClientService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 *
 * @covers  ZfrOAuth2Test\Server\Container\ClientServiceFactory
 */
class ClientServiceFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCreateFromFactory()
    {
        $container       = $this->getMock(ContainerInterface::class);
        $managerRegistry = $this->getMock(ManagerRegistry::class, [], [], '', false);
        $serverOptions   = new ServerOptions(['object_manager' => 'my_object_manager']);
        $objectManager   = $this->getMock(ObjectManager::class);

        $container->expects($this->at(0))
            ->method('get')
            ->with(ManagerRegistry::class)
            ->willReturn($managerRegistry);

        $container->expects($this->at(1))
            ->method('get')
            ->with(ServerOptions::class)
            ->willReturn($serverOptions);

        $managerRegistry->expects($this->at(0))
            ->method('getManager')
            ->with($serverOptions->getObjectManager())
            ->willReturn($objectManager);

        $objectManager->expects($this->at(0))
            ->method('getRepository')
            ->with(Client::class)
            ->willReturn($this->getMock(ObjectRepository::class));

        $factory = new ClientServiceFactory();
        $service = $factory($container);

        $this->assertInstanceOf(ClientService::class, $service);
    }
}
