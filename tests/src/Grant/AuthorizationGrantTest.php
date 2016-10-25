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
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Grant\AuthorizationGrant;
use ZfrOAuth2\Server\Grant\RefreshTokenGrant;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\AuthorizationCode;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\AuthorizationCodeService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Grant\AuthorizationGrant
 */
class AuthorizationGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var AuthorizationCodeService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $authorizationCodeService;

    /**
     * @var AccessTokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $accessTokenService;

    /**
     * @var RefreshTokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $refreshTokenService;

    /**
     * @var AuthorizationGrant
     */
    protected $grant;

    public function setUp()
    {
        $this->authorizationCodeService = $this->createMock(AuthorizationCodeService::class);
        $this->accessTokenService       = $this->createMock(AccessTokenService::class);
        $this->refreshTokenService      = $this->createMock(RefreshTokenService::class);

        $this->grant = new AuthorizationGrant($this->authorizationCodeService, $this->accessTokenService, $this->refreshTokenService);
    }

    public function testAssertInvalidIfWrongResponseType()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_request');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getQueryParams')->will(static::returnValue(['response_type' => 'foo']));

        $this->grant->createAuthorizationResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testCanCreateAuthorizationCodeUsingClientRedirectUri()
    {
        $queryParams = ['response_type' => 'code', 'scope' => '', 'state' => 'xyz'];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getQueryParams')->will(static::returnValue($queryParams));

        $token = $this->getValidAuthorizationCode();
        $this->authorizationCodeService->expects(static::once())->method('createToken')->will(static::returnValue($token));

        $response = $this->grant->createAuthorizationResponse($request, Client::createNewClient('name', 'http://www.example.com'));

        $location = $response->getHeaderLine('Location');
        static::assertEquals('http://www.example.com?code=azerty_auth&state=xyz', $location);
    }

    public function testCanCreateAuthorizationCodeUsingOverriddenRedirectUriInList()
    {
        $queryParams = [
            'response_type' => 'code',
            'scope'         => '',
            'state'         => 'xyz',
            'redirect_uri'  => 'http://www.custom-example.com'
        ];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getQueryParams')->will(static::returnValue($queryParams));

        $token = $this->getValidAuthorizationCode();
        $this->authorizationCodeService->expects(static::once())->method('createToken')->will(static::returnValue($token));

        $client = Client::reconstitute(
            [
                'id'           => 'id',
                'name'         => 'name',
                'secret'       => '',
                'redirectUris' => ['http://www.example.com','http://www.custom-example.com']
            ]
        );

        $response = $this->grant->createAuthorizationResponse($request, $client);

        $location = $response->getHeaderLine('Location');
        static::assertEquals('http://www.custom-example.com?code=azerty_auth&state=xyz', $location);
    }

    public function testTriggerExceptionIfCustomRedirectUriIsNotAuthorized()
    {
        $this->setExpectedException(OAuth2Exception::class);

        $queryParams = [
            'response_type' => 'code',
            'scope'         => '',
            'state'         => 'xyz',
            'redirect_uri'  => 'http://www.custom-example.com'
        ];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getQueryParams')->will(static::returnValue($queryParams));

        $token = $this->getValidAuthorizationCode();
        $this->authorizationCodeService->expects(static::never())->method('createToken')->will(static::returnValue($token));

        $this->grant->createAuthorizationResponse($request, Client::createNewClient('name', 'http://www.example.com'));
    }

    public function testAssertInvalidIfNoCodeIsSet()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn([]);

        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_request');
        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testAssertInvalidGrantIfCodeIsInvalid()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_grant');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn(['code' => '123']);

        $this->authorizationCodeService->expects(static::once())
            ->method('getToken')
            ->with('123')
            ->will(static::returnValue(null));

        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testAssertInvalidGrantIfCodeIsExpired()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_grant');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn(['code' => '123']);

        $this->authorizationCodeService->expects(static::once())
            ->method('getToken')
            ->with('123')
            ->will(static::returnValue($this->getInvalidAuthorizationCode()));

        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testInvalidRequestIfAuthClientIsNotSame()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_request');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn(['code' => '123', 'client_id' => 'foo']);

        $token = $this->getValidAuthorizationCode(null, null, CLient::createNewClient('id', 'http://www.example.com'));

        $this->authorizationCodeService->expects(static::once())
            ->method('getToken')
            ->with('123')
            ->will(static::returnValue($token));

        $this->grant->createTokenResponse($request, CLient::createNewClient('id', 'http://www.example.com'));
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
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn(['code'      => '123',
                                                                               'client_id' => 'client_123'
        ]);

        $client = Client::reconstitute(
            [
                'id'           => 'client_123',
                'name'         => 'name',
                'secret'       => '',
                'redirectUris' => []
            ]
        );
        $token = $this->getValidAuthorizationCode(null, null, $client);

        $this->authorizationCodeService->expects(static::once())
            ->method('getToken')
            ->with('123')
            ->will(static::returnValue($token));

        $owner = $this->createMock(TokenOwnerInterface::class);
        $owner->expects(static::once())->method('getTokenOwnerId')->will(static::returnValue(1));

        $accessToken = $this->getValidAccessToken($owner);
        $this->accessTokenService->expects(static::once())->method('createToken')->will(static::returnValue($accessToken));

        if ($hasRefreshGrant) {
            $refreshToken = $this->getValidRefreshToken();
            $this->refreshTokenService->expects(static::once())->method('createToken')->will(static::returnValue($refreshToken));
        }

        $authorizationServer = $this->createMock(AuthorizationServer::class);
        $authorizationServer->expects(static::once())
            ->method('hasGrant')
            ->with(RefreshTokenGrant::GRANT_TYPE)
            ->will(static::returnValue($hasRefreshGrant));

        $this->grant = new AuthorizationGrant($this->authorizationCodeService, $this->accessTokenService,
            $this->refreshTokenService);
        $this->grant->setAuthorizationServer($authorizationServer);

        $response = $this->grant->createTokenResponse($request, $client, $owner);

        $body = json_decode($response->getBody(), true);

        static::assertEquals('azerty_access', $body['access_token']);
        static::assertEquals('Bearer', $body['token_type']);
        static::assertEquals(3600, $body['expires_in']);
        static::assertEquals('read', $body['scope']);
        static::assertEquals(1, $body['owner_id']);

        if ($hasRefreshGrant) {
            static::assertEquals('azerty_refresh', $body['refresh_token']);
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

    /**
     * @return AuthorizationCode
     */
    private function getInvalidAuthorizationCode($redirectUri = null, $owner = null, $client = null, $scopes = null)
    {
        $invalidDate = (new \DateTimeImmutable())->sub(new DateInterval('PT1H'));
        $token     = AuthorizationCode::reconstitute([
            'token'     => 'azerty_auth',
            'owner'     => $owner,
            'client'    => $client,
            'scopes'    => $scopes ?? ['read'],
            'expiresAt' => $invalidDate,
            'redirectUri' => $redirectUri ?? ''
        ]);

        return $token;
    }

    /**
     * @return AuthorizationCode
     */
    private function getValidAuthorizationCode($redirectUri = null, $owner = null, $client = null, $scopes = null)
    {
        $validDate = (new \DateTimeImmutable())->add(new DateInterval('PT1H'));
        $token     = AuthorizationCode::reconstitute([
            'token'     => 'azerty_auth',
            'owner'     => $owner,
            'client'    => $client,
            'scopes'    => $scopes ?? ['read'],
            'expiresAt' => $validDate,
            'redirectUri' => $redirectUri ?? ''
        ]);

        return $token;
    }
}
