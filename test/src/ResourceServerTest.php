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

namespace ZfrOAuth2Test\Server;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\Exception\InvalidAccessTokenException;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\ResourceServer;
use ZfrOAuth2\Server\Service\AccessTokenService;

use function explode;

/**
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\ResourceServer
 */
class ResourceServerTest extends TestCase
{
    /** @var AccessTokenService|MockObject */
    protected $tokenService;

    /** @var ResourceServer */
    protected $resourceServer;

    public function setUp(): void
    {
        $this->tokenService   = $this->createMock(AccessTokenService::class);
        $this->resourceServer = new ResourceServer($this->tokenService);
    }

    public function testCanExtractAccessTokenFromAuthorizationHeader(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(true));
        $request->expects($this->once())->method('getHeaderLine')->will($this->returnValue('Bearer token'));

        $token = $this->createMock(AccessToken::class);
        $token->expects($this->once())->method('isValid')->will($this->returnValue(true));

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue($token));

        $this->assertSame($token, $this->resourceServer->getAccessToken($request));
    }

    public function testCanExtractAccessTokenFromQueryString(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);

        $request
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')->will($this->returnValue(false));

        $request
            ->expects($this->once())
            ->method('getQueryParams')
            ->will($this->returnValue(['access_token' => 'token']));

        $token = $this->createMock(AccessToken::class);

        $token
            ->expects($this->once())
            ->method('isValid')
            ->will($this->returnValue(true));

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue($token));

        $this->assertSame($token, $this->resourceServer->getAccessToken($request));
    }

    public function testReturnNullIfNoAccessTokenIsInAuthorizationHeader()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(true));
        $request->expects($this->once())->method('getHeaderLine')->will($this->returnValue(''));

        $this->assertNull($this->resourceServer->getAccessToken($request));
    }

    public function testThrowExceptionIfTokenDoesNotExistAnymore(): void
    {
        $this->expectException(InvalidAccessTokenException::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(true));
        $request->expects($this->once())->method('getHeaderLine')->will($this->returnValue('Bearer token'));

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue(null));

        $this->resourceServer->getAccessToken($request);
    }

    public function requestProvider(): array
    {
        return [
            // Should return false because the token is expired
            [
                'expired_token' => true,
                'token_scope'   => 'read',
                'desired_scope' => 'read write',
                'match'         => false,
            ],

            // Should return false because we are asking more permissions than the token scope
            [
                'expired_token' => false,
                'token_scope'   => 'read',
                'desired_scope' => 'read write',
                'match'         => false,
            ],

            // Should return true
            [
                'expired_token' => false,
                'token_scope'   => 'read',
                'desired_scope' => 'read',
                'match'         => true,
            ],
        ];
    }

    /**
     * @dataProvider requestProvider
     */
    public function testCanValidateAccessToResource(
        bool $expiredToken,
        string $tokenScope,
        string $desiredScope,
        bool $match
    ): void {
        $tokenScope = explode(' ', $tokenScope);
        $request    = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(true));
        $request->expects($this->once())->method('getHeaderLine')->will($this->returnValue('Bearer token'));

        if ($expiredToken) {
            $accessToken = AccessToken::createNewAccessToken(-3600, null, null, $tokenScope);
        } else {
            $accessToken = AccessToken::createNewAccessToken(3600, null, null, $tokenScope);
        }

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue($accessToken));

        if (! $match || $expiredToken) {
            $this->expectException(InvalidAccessTokenException::class);
        }

        $tokenResult = $this->resourceServer->getAccessToken($request, $desiredScope);
        $this->assertInstanceOf(AccessToken::class, $tokenResult);
    }
}
