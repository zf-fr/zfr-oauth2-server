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

namespace ZfrOAuth2Test\Server\Factory;

use Doctrine\Common\Persistence\ManagerRegistry;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use Interop\Container\ContainerInterface;
use ZfrOAuth2\Server\Container\ResourceServerFactory;
use ZfrOAuth2\Server\Container\ScopeServiceFactory;
use ZfrOAuth2\Server\Entity\Scope;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Service\ScopeService;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 *
 * @covers  ZfrOAuth2\Server\Factory\ScopeServiceFactory
 */
class ScopeServiceFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCreateFromFactory()
    {
        $container    = $this->getMock(ContainerInterface::class);
        $serverOptions = new ServerOptions(['object_manager' => 'my_object_manager']);

        $objectManager = $this->getMock(ObjectManager::class);
        $objectManager->expects($this->at(0))
            ->method('getRepository')
            ->with(Scope::class)
            ->willReturn($this->getMock(ObjectRepository::class));

        $managerRegistry = $this->getMock(ManagerRegistry::class, [], [], '', false);
        $managerRegistry->expects($this->once())
            ->method('getManager')
            ->with($serverOptions->getObjectManager())
            ->willReturn($objectManager);

        $container->expects($this->at(0))
            ->method('get')
            ->with(ManagerRegistry::class)
            ->willReturn($managerRegistry);

        $container->expects($this->at(1))
            ->method('get')
            ->with(ServerOptions::class)
            ->willReturn($serverOptions);

        $factory = new ScopeServiceFactory();
        $service = $factory($container);

        $this->assertInstanceOf(ScopeService::class, $service);
    }
}
