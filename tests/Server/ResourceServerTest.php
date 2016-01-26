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

use DateInterval;
use DateTime;
use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Exception\InvalidAccessTokenException;
use ZfrOAuth2\Server\ResourceServer;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\ResourceServer
 */
class ResourceServerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var TokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $tokenService;

    /**
     * @var ResourceServer
     */
    protected $resourceServer;

    public function setUp()
    {
        $this->tokenService   = $this->getMock(TokenService::class, [], [], '', false);
        $this->resourceServer = new ResourceServer($this->tokenService);
    }

    public function testCanExtractAccessTokenFromAuthorizationHeader()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(true));
        $request->expects($this->once())->method('getHeaderLine')->will($this->returnValue('Bearer token'));

        $token = $this->getMock(AccessToken::class);
        $token->expects($this->once())->method('isValid')->will($this->returnValue(true));

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue($token));

        $this->assertSame($token, $this->resourceServer->getAccessToken($request));
    }

    public function testCanExtractAccessTokenFromQueryString()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(false));
        $request->expects($this->once())->method('getQueryParams')->will($this->returnValue(['access_token' => 'token']));

        $token = $this->getMock(AccessToken::class);
        $token->expects($this->once())->method('isValid')->will($this->returnValue(true));

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue($token));

        $this->assertSame($token, $this->resourceServer->getAccessToken($request));
    }

    public function testReturnNullIfNoAccessTokenIsInAuthorizationHeader()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(true));
        $request->expects($this->once())->method('getHeaderLine')->will($this->returnValue(''));

        $this->assertNull($this->resourceServer->getAccessToken($request));
    }

    public function testThrowExceptionIfTokenDoesNotExistAnymore()
    {
        $this->setExpectedException(InvalidAccessTokenException::class);

        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(true));
        $request->expects($this->once())->method('getHeaderLine')->will($this->returnValue('Bearer token'));

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue(null));

        $this->resourceServer->getAccessToken($request);
    }

    public function requestProvider()
    {
        return [
            // Should return false because the token is expired
            [
                'expired_token' => true,
                'token_scope'   => 'read',
                'desired_scope' => 'read write',
                'match'         => false
            ],

            // Should return false because we are asking more permissions than the token scope
            [
                'expired_token' => false,
                'token_scope'   => 'read',
                'desired_scope' => 'read write',
                'match'         => false
            ],

            // Should return true
            [
                'expired_token' => false,
                'token_scope'   => 'read',
                'desired_scope' => 'read',
                'match'         => true
            ],
        ];
    }

    /**
     * @dataProvider requestProvider
     */
    public function testCanValidateAccessToResource($expiredToken, $tokenScope, $desiredScope, $match)
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('hasHeader')->with('Authorization')->will($this->returnValue(true));
        $request->expects($this->once())->method('getHeaderLine')->will($this->returnValue('Bearer token'));

        $accessToken = new AccessToken();
        $date        = new DateTime();

        if ($expiredToken) {
            $date->sub(new DateInterval('P1D'));
        } else {
            $date->add(new DateInterval('P1D'));
        }

        $accessToken->setExpiresAt($date);
        $accessToken->setScopes($tokenScope);

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue($accessToken));

        if (!$match || $expiredToken) {
            $this->setExpectedException(InvalidAccessTokenException::class);
        }

        $tokenResult = $this->resourceServer->getAccessToken($request, $desiredScope);
        $this->assertInstanceOf(AccessToken::class, $tokenResult);
    }
}
