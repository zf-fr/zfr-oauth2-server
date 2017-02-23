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

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface as RequestInterface;
use Zend\Diactoros\Response\JsonResponse;
use ZfrOAuth2\Server\Exception\InvalidAccessTokenException;
use ZfrOAuth2\Server\Middleware\ResourceServerMiddleware;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\ResourceServer;

/**
 * @author  Bas Kamer <baskamer@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Middleware\ResourceServerMiddleware
 */
class ResourceServerMiddlewareTest extends TestCase
{
    public function testWillGetAccessTokenWithAccessTokenAsResult()
    {
        $resourceServer = $this->createMock(ResourceServer::class);
        $middleware     = new ResourceServerMiddleware($resourceServer);
        $accessToken    = $this->createMock(AccessToken::class);
        $request        = $this->createMock(RequestInterface::class);
        $response       = $this->createMock(ResponseInterface::class);

        $resourceServer->expects($this->once())
            ->method('getAccessToken')
            ->with($request)
            ->willReturn($accessToken);

        $request->expects($this->once())
            ->method('withAttribute')
            ->with(
                'oauth_token',
                $accessToken
            )
            ->willReturn($request);

        $middleware($request, $response, function ($request, $response) {
            return $response;
        });
    }

    public function testWillGetAccessTokenWithNullAsResult()
    {
        $resourceServer = $this->createMock(ResourceServer::class);
        $middleware     = new ResourceServerMiddleware($resourceServer);
        $accessToken    = null;
        $request        = $this->createMock(RequestInterface::class);
        $response       = $this->createMock(ResponseInterface::class);

        $resourceServer->expects($this->once())
            ->method('getAccessToken')
            ->with($request)
            ->willReturn($accessToken);

        $request->expects($this->once())
            ->method('withAttribute')
            ->with(
                'oauth_token',
                $accessToken
            )
            ->willReturn($request);

        $middleware($request, $response, function ($request, $response) {
            return $response;
        });
    }

    public function testWillCallGetAccessTokenWithException()
    {
        $resourceServer = $this->createMock(ResourceServer::class);
        $middleware     = new ResourceServerMiddleware($resourceServer);
        $accessToken    = null;
        $request        = $this->createMock(RequestInterface::class);
        $response       = $this->createMock(ResponseInterface::class);

        $resourceServer->expects($this->once())
            ->method('getAccessToken')
            ->with($request)
            ->willThrowException(new InvalidAccessTokenException('error message'));

        $result = $middleware($request, $response, function ($request, $response) {
            return $response;
        });

        $this->assertInstanceOf(JsonResponse::class, $result);

        $this->assertSame(401, $result->getStatusCode());
        $this->assertSame('{"error":"error message"}', (string) $result->getBody());
    }
}