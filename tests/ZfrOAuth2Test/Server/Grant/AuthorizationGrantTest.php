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
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\AuthorizationCode;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Grant\AuthorizationGrant;
use ZfrOAuth2\Server\Grant\PasswordGrant;
use ZfrOAuth2\Server\Grant\RefreshTokenGrant;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Grant\AuthorizationGrant
 */
class AuthorizationGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var TokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $authorizationCodeService;

    /**
     * @var TokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $accessTokenService;

    /**
     * @var TokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $refreshTokenService;

    /**
     * @var PasswordGrant
     */
    protected $grant;

    public function setUp()
    {
        $this->authorizationCodeService = $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false);
        $this->accessTokenService       = $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false);
        $this->refreshTokenService      = $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false);

        $this->grant = new AuthorizationGrant($this->authorizationCodeService, $this->accessTokenService, $this->refreshTokenService);
    }

    public function testAssertInvalidIfWrongResponseType()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_request');

        $request = new HttpRequest();
        $request->getQuery()->set('response_type', 'foo');

        $this->grant->createAuthorizationResponse($request, new Client());
    }

    public function testCanCreateAuthorizationCodeUsingClientRedirectUri()
    {
        $request = new HttpRequest();
        $request->getQuery()->fromArray(['response_type' => 'code', 'scope' => '', 'state' => 'xyz']);

        $token = $this->getValidAuthorizationCode();
        $this->authorizationCodeService->expects($this->once())->method('createToken')->will($this->returnValue($token));

        $client   = new Client();
        $client->setRedirectUri('http://www.example.com');
        $response = $this->grant->createAuthorizationResponse($request, $client);

        $location = $response->getHeaders()->get('Location')->getFieldValue();
        $this->assertEquals('http://www.example.com/?code=azerty_auth&state=xyz', $location);
    }

    public function testCanCreateAuthorizationCodeUsingOverriddenRedirectUri()
    {
        $request = new HttpRequest();
        $request->getQuery()->fromArray([
            'response_type' => 'code',
            'scope'         => '',
            'state'         => 'xyz',
            'redirect_uri'  => 'http://www.custom-example.com'
        ]);

        $token = $this->getValidAuthorizationCode();
        $this->authorizationCodeService->expects($this->once())->method('createToken')->will($this->returnValue($token));

        $client   = new Client();
        $client->setRedirectUri('http://www.example.com');
        $response = $this->grant->createAuthorizationResponse($request, $client);

        $location = $response->getHeaders()->get('Location')->getFieldValue();
        $this->assertEquals('http://www.custom-example.com/?code=azerty_auth&state=xyz', $location);
    }

    public function testAssertInvalidIfNoCodeIsSet()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_request');
        $this->grant->createTokenResponse(new HttpRequest(), new Client());
    }

    public function testAssertInvalidGrantIfCodeIsInvalid()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_grant');

        $request = new HttpRequest();
        $request->getPost()->set('code', '123');

        $this->authorizationCodeService->expects($this->once())
                                       ->method('getToken')
                                       ->with('123')
                                       ->will($this->returnValue(null));

        $this->grant->createTokenResponse($request, new Client());
    }

    public function testAssertInvalidGrantIfCodeIsExpired()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_grant');

        $request = new HttpRequest();
        $request->getPost()->set('code', '123');

        $this->authorizationCodeService->expects($this->once())
                                       ->method('getToken')
                                       ->with('123')
                                       ->will($this->returnValue($this->getInvalidAuthorizationCode()));

        $this->grant->createTokenResponse($request, new Client());
    }

    public function testInvalidRequestIfAuthClientIsNotSame()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_request');

        $request = new HttpRequest();
        $request->getPost()->set('code', '123')
                           ->set('client_id', 'foo');

        $token = $this->getValidAuthorizationCode();
        $token->setClient(new Client());

        $this->authorizationCodeService->expects($this->once())
                                       ->method('getToken')
                                       ->with('123')
                                       ->will($this->returnValue($token));

        $this->grant->createTokenResponse($request, new Client());
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
        $request = new HttpRequest();
        $request->getPost()->fromArray(['code' => '123', 'client_id' => 'client_123']);

        $token  = $this->getValidAuthorizationCode();

        $client = new Client();

        // We use reflection because there is no setter on client
        $reflProperty = new \ReflectionProperty($client, 'id');
        $reflProperty->setAccessible(true);
        $reflProperty->setValue($client, 'client_123');

        $token->setClient($client);

        $this->authorizationCodeService->expects($this->once())
                                       ->method('getToken')
                                       ->with('123')
                                       ->will($this->returnValue($token));

        $owner = $this->getMock('ZfrOAuth2\Server\Entity\TokenOwnerInterface');
        $owner->expects($this->once())->method('getTokenOwnerId')->will($this->returnValue(1));

        $accessToken = $this->getValidAccessToken();
        $this->accessTokenService->expects($this->once())->method('createToken')->will($this->returnValue($accessToken));

        if ($hasRefreshGrant) {
            $refreshToken = $this->getValidRefreshToken();
            $this->refreshTokenService->expects($this->once())->method('createToken')->will($this->returnValue($refreshToken));
        }

        $authorizationServer = $this->getMock('ZfrOAuth2\Server\AuthorizationServer', [], [], '', false);
        $authorizationServer->expects($this->once())
                            ->method('hasGrant')
                            ->with(RefreshTokenGrant::GRANT_TYPE)
                            ->will($this->returnValue($hasRefreshGrant));

        $this->grant = new AuthorizationGrant($this->authorizationCodeService, $this->accessTokenService, $this->refreshTokenService);
        $this->grant->setAuthorizationServer($authorizationServer);

        $response = $this->grant->createTokenResponse($request, new Client(), $owner);

        $body = json_decode($response->getContent(), true);

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

    /**
     * @return AccessToken
     */
    private function getInvalidAuthorizationCode()
    {
        $authorizationCode = new AuthorizationCode();
        $authorizationCode->setToken('azerty_auth');
        $authorizationCode->setScopes('read');
        $invalidDate   = new DateTime();
        $invalidDate->sub(new DateInterval('PT1H'));

        $authorizationCode->setExpiresAt($invalidDate);

        return $authorizationCode;
    }

    /**
     * @return AccessToken
     */
    private function getValidAuthorizationCode()
    {
        $authorizationCode = new AuthorizationCode();
        $authorizationCode->setToken('azerty_auth');
        $authorizationCode->setScopes('read');
        $validDate   = new DateTime();
        $validDate->add(new DateInterval('PT1H'));

        $authorizationCode->setExpiresAt($validDate);

        return $authorizationCode;
    }
}
