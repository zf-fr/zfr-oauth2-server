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

namespace ZfrOAuth2Test\Server\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface as RequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ZfrOAuth2\Server\AuthorizationServerInterface;
use ZfrOAuth2\Server\Middleware\RevocationRequestMiddleware;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Middleware\RevocationRequestMiddleware
 */
class RevocationRequestMiddlewareTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject|AuthorizationServerInterface
     */
    private $authorizationServer;

    /**
     * @var RevocationRequestMiddleware
     */
    private $middleware;

    public function setUp(): void
    {
        $this->authorizationServer = $this->createMock(AuthorizationServerInterface::class);
        $this->middleware = new RevocationRequestMiddleware($this->authorizationServer);
    }

    public function testCanHandleRevocationRequest(): void
    {
        $request = $this->createMock(RequestInterface::class);
        $delegate = $this->createMock(RequestHandlerInterface::class);

        $this->authorizationServer->expects($this->once())
            ->method('handleRevocationRequest')
            ->with($request)
            ->willReturn($this->createMock(ResponseInterface::class));

        $this->middleware->process($request, $delegate);
    }
}
