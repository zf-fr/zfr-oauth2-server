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
use Psr\Http\Message\ServerRequestInterface;
use Zend\Http\Request as HttpRequest;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Entity\TokenOwnerInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
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
        $this->accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $this->refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $this->grant = new RefreshTokenGrant($this->accessTokenService, $this->refreshTokenService);
    }

    public function testAssertDoesNotImplementAuthorization()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_request');
        $this->grant->createAuthorizationResponse($this->getMock(ServerRequestInterface::class), new Client());
    }

    public function testAssertInvalidIfNoRefreshTokenIsFound()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn([]);

        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_request');
        $this->grant->createTokenResponse($request, new Client());
    }

    public function testAssertInvalidIfRefreshTokenIsExpired()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_grant');

        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['refresh_token' => '123']);

        $refreshToken = $this->getExpiredRefreshToken();

        $this->refreshTokenService->expects($this->once())
                                  ->method('getToken')
                                  ->with('123')
                                  ->will($this->returnValue($refreshToken));

        $this->grant->createTokenResponse($request, new Client());
    }

    public function testAssertExceptionIfAskedScopeIsSuperiorToRefreshToken()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_scope');

        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['refresh_token' => '123', 'scope' => 'read write']);

        $refreshToken = $this->getValidRefreshToken();
        $refreshToken->setScopes(['read']);

        $this->refreshTokenService->expects($this->once())
                                   ->method('getToken')
                                   ->with('123')
                                   ->will($this->returnValue($refreshToken));

        $this->grant->createTokenResponse($request, new Client());
    }

    public function rotateRefreshToken()
    {
        return [
            [true],
            [false]
        ];
    }

    /**
     * @dataProvider rotateRefreshToken
     */
    public function testCanCreateTokenResponse($rotateRefreshToken)
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['refresh_token' => '123', 'scope' => 'read']);

        $owner = $this->getMock(TokenOwnerInterface::class);
        $owner->expects($this->once())->method('getTokenOwnerId')->will($this->returnValue(1));

        $refreshToken = $this->getValidRefreshToken();
        $refreshToken->setScopes(['read']);
        $refreshToken->setOwner($owner);

        $this->refreshTokenService->expects($this->once())
                                  ->method('getToken')
                                  ->with('123')
                                  ->will($this->returnValue($refreshToken));

        if ($rotateRefreshToken) {
            $this->refreshTokenService->expects($this->once())
                                      ->method('deleteToken')
                                      ->with($refreshToken);

            $refreshToken = $this->getValidRefreshToken();
            $this->refreshTokenService->expects($this->once())->method('createToken')->will($this->returnValue($refreshToken));
        }

        $accessToken = $this->getValidAccessToken();
        $accessToken->setOwner($owner);
        $this->accessTokenService->expects($this->once())->method('createToken')->will($this->returnValue($accessToken));

        $this->grant->setRotateRefreshTokens($rotateRefreshToken);
        $response = $this->grant->createTokenResponse($request, new Client());

        $body = json_decode($response->getBody(), true);

        $this->assertEquals('azerty_access', $body['access_token']);
        $this->assertEquals('Bearer', $body['token_type']);
        $this->assertEquals(3600, $body['expires_in']);
        $this->assertEquals('read', $body['scope']);
        $this->assertEquals(1, $body['owner_id']);
        $this->assertEquals('azerty_refresh', $body['refresh_token']);
    }

    /**
     * @return RefreshToken
     */
    private function getExpiredRefreshToken()
    {
        $refreshToken = new RefreshToken();
        $expiredDate  = new DateTime();
        $expiredDate->sub(new DateInterval('P1D'));

        $refreshToken->setExpiresAt($expiredDate);

        return $refreshToken;
    }

    /**
     * @return RefreshToken
     */
    private function getValidRefreshToken()
    {
        $refreshToken = new RefreshToken();
        $refreshToken->setToken('azerty_refresh');
        $refreshToken->setScopes('read');
        $validDate    = new DateTime();
        $validDate->add(new DateInterval('P1D'));

        $refreshToken->setExpiresAt($validDate);

        return $refreshToken;
    }

    /**
     * @return AccessToken
     */
    private function getValidAccessToken()
    {
        $accessToken = new AccessToken();
        $accessToken->setToken('azerty_access');
        $accessToken->setScopes('read');
        $validDate   = new DateTime();
        $validDate->add(new DateInterval('PT1H'));

        $accessToken->setExpiresAt($validDate);

        return $accessToken;
    }
}
