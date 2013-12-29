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

namespace ZfrOAuth2Test\Server\Grant;

use DateInterval;
use DateTime;
use Zend\Http\Request as HttpRequest;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Grant\RefreshTokenGrant;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Grant\RefreshTokenGrant
 */
class RefreshTokenGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var TokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $accessTokenService;

    /**
     * @var TokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $refreshTokenService;

    /**
     * @var RefreshTokenGrant
     */
    protected $grant;

    public function setUp()
    {
        $this->accessTokenService  = $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false);
        $this->refreshTokenService = $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false);

        $this->grant = new RefreshTokenGrant($this->accessTokenService, $this->refreshTokenService);
    }

    public function testAssertDoesNotImplementAuthorization()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_request');
        $this->grant->createAuthorizationResponse(new HttpRequest(), new Client());
    }

    public function testAssertInvalidIfNoRefreshTokenIsFound()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_request');
        $this->grant->createTokenResponse(new HttpRequest(), new Client());
    }

    public function testAssertInvalidIfRefreshTokenIsExpired()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_grant');

        $request = new HttpRequest();
        $request->getPost()->set('refresh_token', '123');

        $refreshToken = new RefreshToken();
        $expiredDate  = new DateTime();
        $expiredDate->sub(new DateInterval('P1D'));

        $this->refreshTokenService->expects($this->once())
                                  ->method('getToken')
                                  ->with('123')
                                  ->will($this->returnValue($refreshToken));

        $this->grant->createTokenResponse($request, new Client());
    }
}
