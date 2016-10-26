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

namespace ZfrOAuth2Test\Server\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface as RequestInterface;
use ZfrOAuth2\Server\AuthorizationServerInterface;
use ZfrOAuth2\Server\Middleware\TokenRequestMiddleware;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Middleware\TokenRequestMiddleware
 */
class TokenRequestMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject|AuthorizationServerInterface
     */
    private $authorizationServer;

    /**
     * @var TokenRequestMiddleware
     */
    private $middleware;

    public function setUp()
    {
        $this->authorizationServer = $this->createMock(AuthorizationServerInterface::class);
        $this->middleware          = new TokenRequestMiddleware($this->authorizationServer);
    }

    public function testCanHandleTokenRequest()
    {
        $request  = $this->createMock(RequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $next = function() {};

        $this->authorizationServer->expects($this->once())
            ->method('handleTokenRequest')
            ->with($request)
            ->willReturn($this->createMock(ResponseInterface::class));

        $middleware = $this->middleware;
        $middleware ($request, $response, $next);
    }
}