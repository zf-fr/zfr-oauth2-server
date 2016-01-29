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
use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\AuthorizationServer;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Grant\PasswordGrant;
use ZfrOAuth2\Server\Grant\RefreshTokenGrant;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Grant\PasswordGrant
 */
class PasswordGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var AccessTokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $accessTokenService;

    /**
     * @var RefreshTokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $refreshTokenService;

    /**
     * @var callable
     */
    protected $callback;

    /**
     * @var PasswordGrant
     */
    protected $grant;

    public function setUp()
    {
        $this->accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $this->refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $callable    = function(){};
        $this->grant = new PasswordGrant($this->accessTokenService, $this->refreshTokenService, $callable);
    }

    public function testAssertDoesNotImplementAuthorization()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_request');
        $this->grant->createAuthorizationResponse($this->getMock(ServerRequestInterface::class), Client::createNewClient('id', 'name'));
    }

    public function testAssertInvalidIfNoUsernameNorPasswordIsFound()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn([]);

        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_request');
        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'name'));
    }

    public function testAssertInvalidIfWrongCredentials()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'access_denied');

        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['username' => 'michael', 'password' => 'azerty']);

        $callable = function($username, $password) {
            $this->assertEquals('michael', $username);
            $this->assertEquals('azerty', $password);

            return false;
        };

        $this->grant = new PasswordGrant($this->accessTokenService, $this->refreshTokenService, $callable);

        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'name'));
    }

    public function hasRefreshGrant()
    {
        return [
            [true],
            [false]
        ];
    }

    /**
     * @dataProvider hasRefreshGrant
     */
    public function testCanCreateTokenResponse($hasRefreshGrant)
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['username' => 'michael', 'password' => 'azerty', 'scope' => 'read']);

        $owner = $this->getMock(TokenOwnerInterface::class);
        $owner->expects($this->once())->method('getTokenOwnerId')->will($this->returnValue(1));

        $callable = function($username, $password) use ($owner) {
            return $owner;
        };

        $accessToken = $this->getValidAccessToken($owner);
        $this->accessTokenService->expects($this->once())->method('createToken')->will($this->returnValue($accessToken));

        if ($hasRefreshGrant) {
            $refreshToken = $this->getValidRefreshToken();
            $this->refreshTokenService->expects($this->once())->method('createToken')->will($this->returnValue($refreshToken));
        }

        $authorizationServer = $this->getMock(AuthorizationServer::class, [], [], '', false);
        $authorizationServer->expects($this->once())
                            ->method('hasGrant')
                            ->with(RefreshTokenGrant::GRANT_TYPE)
                            ->will($this->returnValue($hasRefreshGrant));

        $this->grant = new PasswordGrant($this->accessTokenService, $this->refreshTokenService, $callable);
        $this->grant->setAuthorizationServer($authorizationServer);

        $response = $this->grant->createTokenResponse($request, Client::createNewClient('id', 'name'));

        $body = json_decode($response->getBody(), true);

        $this->assertEquals('azerty_access', $body['access_token']);
        $this->assertEquals('Bearer', $body['token_type']);
        $this->assertEquals(3600, $body['expires_in']);
        $this->assertEquals('read', $body['scope']);
        $this->assertEquals(1, $body['owner_id']);

        if ($hasRefreshGrant) {
            $this->assertEquals('azerty_refresh', $body['refresh_token']);
        }
    }

    /**
     * @return RefreshToken
     */
    private function getValidRefreshToken(TokenOwnerInterface $owner = null, array $scopes = null)
    {
        $validDate = (new \DateTimeImmutable())->add(new DateInterval('P1D'));
        $token     = RefreshToken::reconstitute([
            'token'     => 'azerty_refresh',
            'owner'     => $owner,
            'client'    => null,
            'scopes'    => $scopes ?? ['read'],
            'expiresAt' => $validDate
        ]);

        return $token;
    }

    /**
     * @return AccessToken
     */
    private function getValidAccessToken(TokenOwnerInterface $owner = null, array $scopes = null)
    {
        $validDate = (new \DateTimeImmutable())->add(new DateInterval('PT1H'));
        $token     = AccessToken::reconstitute([
            'token'     => 'azerty_access',
            'owner'     => $owner,
            'client'    => null,
            'scopes'    => $scopes ?? ['read'],
            'expiresAt' => $validDate
        ]);

        return $token;
    }
}
