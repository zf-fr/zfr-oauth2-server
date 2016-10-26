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
use ZfrOAuth2\Server\Container\AuthorizationRequestMiddlewareFactory;
use ZfrOAuth2\Server\Container\ResourceServerMiddlewareFactory;
use ZfrOAuth2\Server\Middleware\AuthorizationRequestMiddleware;
use ZfrOAuth2\Server\Middleware\ResourceServerMiddleware;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\ResourceServer;

/**
 * @author  Bas Kamer <baskamer@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Container\ResourceServerMiddlewareFactory
 */
class ResourceServerMiddlewareFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCreateFromFactory()
    {
        $container = $this->createMock(ContainerInterface::class);

        $container->expects($this->at(0))
            ->method('get')
            ->with(ResourceServer::class)
            ->willReturn($this->createMock(ResourceServer::class));

        $factory = new ResourceServerMiddlewareFactory();
        $service = $factory($container);

        $this->assertInstanceOf(ResourceServerMiddleware::class, $service);
    }
}
