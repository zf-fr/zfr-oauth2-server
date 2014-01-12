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
use Zend\Http\Request as HttpRequest;
use ZfrOAuth2\Server\Entity\AccessToken;
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
        $this->tokenService   = $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false);
        $this->resourceServer = new ResourceServer($this->tokenService);
    }

    public function testCanExtractAccessToken()
    {
        $request = new HttpRequest();
        $request->getHeaders()->addHeaderLine('Authorization', 'Bearer token');

        $token = $this->getMock('ZfrOAuth2\Server\Entity\AbstractToken');

        $this->tokenService->expects($this->once())
                           ->method('getToken')
                           ->with('token')
                           ->will($this->returnValue($token));

        $this->assertSame($token, $this->resourceServer->getAccessToken($request));
    }

    public function testThrowExceptionIfNoAccessTokenIsInAuthorizationHeader()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\InvalidAccessTokenException');

        $request = new HttpRequest();
        $request->getHeaders()->addHeaderLine('Authorization', '');

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
                'result'        => false
            ],

            // Should return false because we are asking more permissions than the token scope
            [
                'expired_token' => false,
                'token_scope'   => 'read',
                'desired_scope' => 'read write',
                'result'        => false
            ],

            // Should return true
            [
                'expired_token' => false,
                'token_scope'   => 'read',
                'desired_scope' => 'read',
                'result'        => true
            ],
        ];
    }

    /**
     * @dataProvider requestProvider
     */
    public function testCanValidateAccessToResource($expiredToken, $tokenScope, $desiredScope, $result)
    {
        $request = new HttpRequest();
        $request->getHeaders()->addHeaderLine('Authorization', 'Bearer token');

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

        $this->assertEquals($result, $this->resourceServer->isRequestValid($request, $desiredScope));
    }
}
