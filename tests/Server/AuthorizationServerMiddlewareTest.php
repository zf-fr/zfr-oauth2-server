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

namespace ZfrOAuth2Test\Server;

use Psr\Http\Message\ServerRequestInterface as RequestInterface;
use Psr\Http\Message\ResponseInterface;
use ZfrOAuth2\Server\AuthorizationServerMiddleware;
use ZfrOAuth2\Server\AuthorizationServerInterface;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\AuthorizationServerMiddleware
 */
class AuthorizationServerMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject|AuthorizationServerInterface
     */
    private $authorizationServer;

    /**
     * @var AuthorizationServerMiddleware
     */
    private $authorizationMiddleware;

    public function setUp()
    {
        $this->authorizationServer     = $this->getMock(AuthorizationServerInterface::class);
        $this->authorizationMiddleware = new AuthorizationServerMiddleware($this->authorizationServer);
    }

    public function testCanHandleTokenRequest()
    {
        $request  = $this->getMock(RequestInterface::class);
        $response = $this->getMock(ResponseInterface::class);

        $this->authorizationServer->expects($this->once())->method('handleTokenRequest')->with($request);
        $this->authorizationMiddleware->handleTokenRequest($request, $response);
    }

    public function testCanHandleRevocationRequest()
    {
        $request  = $this->getMock(RequestInterface::class);
        $response = $this->getMock(ResponseInterface::class);

        $this->authorizationServer->expects($this->once())->method('handleRevocationRequest')->with($request);
        $this->authorizationMiddleware->handleRevocationRequest($request, $response);
    }
}