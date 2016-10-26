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
use ZfrOAuth2\Server\Container\ScopeServiceFactory;
use ZfrOAuth2\Server\Container\TokenRequestMiddlewareFactory;
use ZfrOAuth2\Server\Middleware\TokenRequestMiddleware;
use ZfrOAuth2\Server\Repository\ScopeRepositoryInterface;
use ZfrOAuth2\Server\Service\ScopeService;

/**
 * @author  Bas Kamer <baskamer@gmail.com>
 * @licence MIT
 *
 * @covers  \ZfrOAuth2\Server\Container\TokenRequestMiddlewareFactory
 */
class TokenRequestMiddlewareFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCreateFromFactory()
    {
        $container = $this->createMock(ContainerInterface::class);

        $container->expects($this->at(0))
            ->method('get')
            ->with(AuthorizationServer::class)
            ->willReturn($this->createMock(AuthorizationServer::class));

        $factory = new TokenRequestMiddlewareFactory();
        $service = $factory($container);

        $this->assertInstanceOf(TokenRequestMiddleware::class, $service);
    }
}
