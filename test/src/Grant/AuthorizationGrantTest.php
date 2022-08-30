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

namespace ZfrOAuth2Test\Server\Grant;

use Carbon\Carbon;
use DateInterval;
use DateTimeImmutable;
use phpmock\phpunit\PHPMock;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
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

use function json_decode;

/**
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Grant\AuthorizationGrant
 */
class AuthorizationGrantTest extends TestCase
{
    use PHPMock;

    /** @var AuthorizationCodeService|MockObject */
    protected $authorizationCodeService;

    /** @var AccessTokenService|MockObject */
    protected $accessTokenService;

    /** @var RefreshTokenService|MockObject */
    protected $refreshTokenService;

    /** @var AuthorizationGrant */
    protected $grant;

    public function setUp(): void
    {
        $this->authorizationCodeService = $this->createMock(AuthorizationCodeService::class);
        $this->accessTokenService       = $this->createMock(AccessTokenService::class);
        $this->refreshTokenService      = $this->createMock(RefreshTokenService::class);

        $this->grant = new AuthorizationGrant(
            $this->authorizationCodeService,
            $this->accessTokenService,
            $this->refreshTokenService
        );
    }

    public function tearDown(): void
    {
        Carbon::setTestNow();
    }

    public function testAssertInvalidIfWrongResponseType(): void
    {
        $this->expectException(OAuth2Exception::class, null, 'invalid_request');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())
            ->method('getQueryParams')
            ->will($this->returnValue(['response_type' => 'foo']));

        $this->grant->createAuthorizationResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testCanCreateAuthorizationCodeUsingClientRedirectUri(): void
    {
        $queryParams = ['response_type' => 'code', 'scope' => '', 'state' => 'xyz'];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())
            ->method('getQueryParams')
            ->will($this->returnValue($queryParams));

        $token = $this->getValidAuthorizationCode();
        $this->authorizationCodeService
            ->expects($this->once())
            ->method('createToken')
            ->will($this->returnValue($token));

        $response = $this->grant->createAuthorizationResponse(
            $request,
            Client::createNewClient('name', 'http://www.example.com')
        );

        $location = $response->getHeaderLine('Location');
        $this->assertEquals('http://www.example.com?code=azerty_auth&state=xyz', $location);
    }

    public function testCanCreateAuthorizationCodeUsingOverriddenRedirectUriInList(): void
    {
        $queryParams = [
            'response_type' => 'code',
            'scope'         => '',
            'state'         => 'xyz',
            'redirect_uri'  => 'http://www.custom-example.com',
        ];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getQueryParams')->will($this->returnValue($queryParams));

        $token = $this->getValidAuthorizationCode();
        $this->authorizationCodeService
            ->expects($this->once())
            ->method('createToken')
            ->will($this->returnValue($token));

        $client = Client::reconstitute(
            [
                'id'           => 'id',
                'name'         => 'name',
                'secret'       => '',
                'redirectUris' => ['http://www.example.com', 'http://www.custom-example.com'],
                'scopes'       => [],
            ]
        );

        $response = $this->grant->createAuthorizationResponse($request, $client);

        $location = $response->getHeaderLine('Location');
        $this->assertEquals('http://www.custom-example.com?code=azerty_auth&state=xyz', $location);
    }

    public function testTriggerExceptionIfCustomRedirectUriIsNotAuthorized(): void
    {
        $this->expectException(OAuth2Exception::class);

        $queryParams = [
            'response_type' => 'code',
            'scope'         => '',
            'state'         => 'xyz',
            'redirect_uri'  => 'http://www.custom-example.com',
        ];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())
            ->method('getQueryParams')
            ->will($this->returnValue($queryParams));

        $token = $this->getValidAuthorizationCode();
        $this->authorizationCodeService
            ->expects($this->never())
            ->method('createToken')
            ->will($this->returnValue($token));

        $this->grant->createAuthorizationResponse($request, Client::createNewClient('name', 'http://www.example.com'));
    }

    public function testAssertInvalidIfNoCodeIsSet(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn([]);

        $this->expectException(OAuth2Exception::class, null, 'invalid_request');
        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testAssertInvalidGrantIfCodeIsInvalid(): void
    {
        $this->expectException(OAuth2Exception::class, null, 'invalid_grant');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['code' => '123']);

        $this->authorizationCodeService->expects($this->once())
            ->method('getToken')
            ->with('123')
            ->will($this->returnValue(null));

        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testAssertInvalidGrantIfCodeIsExpired(): void
    {
        $this->expectException(OAuth2Exception::class, null, 'invalid_grant');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['code' => '123']);

        $this->authorizationCodeService->expects($this->once())
            ->method('getToken')
            ->with('123')
            ->will($this->returnValue($this->getInvalidAuthorizationCode()));

        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testInvalidRequestIfAuthClientIsNotSame(): void
    {
        $this->expectException(OAuth2Exception::class, null, 'invalid_request');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['code' => '123', 'client_id' => 'foo']);

        $token = $this->getValidAuthorizationCode(null, null, Client::createNewClient('id', 'http://www.example.com'));

        $this->authorizationCodeService->expects($this->once())
            ->method('getToken')
            ->with('123')
            ->will($this->returnValue($token));

        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function hasRefreshGrant(): array
    {
        return [
            [true],
            [false],
        ];
    }

    /**
     * @dataProvider hasRefreshGrant
     */
    public function testCanCreateTokenResponse(bool $hasRefreshGrant): void
    {
        Carbon::setTestNow('1970-01-01 02:46:40');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn([
            'code'      => '123',
            'client_id' => 'client_123',
        ]);

        $client = Client::reconstitute(
            [
                'id'           => 'client_123',
                'name'         => 'name',
                'secret'       => '',
                'redirectUris' => [],
                'scopes'       => [],
            ]
        );
        $token  = $this->getValidAuthorizationCode(null, null, $client);

        $this->authorizationCodeService->expects($this->once())
            ->method('getToken')
            ->with('123')
            ->will($this->returnValue($token));

        $owner = $this->createMock(TokenOwnerInterface::class);
        $owner->expects($this->once())->method('getTokenOwnerId')->will($this->returnValue(1));

        $accessToken = $this->getValidAccessToken($owner);
        $this->accessTokenService
            ->expects($this->once())
            ->method('createToken')
            ->will($this->returnValue($accessToken));

        if ($hasRefreshGrant) {
            $refreshToken = $this->getValidRefreshToken();
            $this->refreshTokenService
                ->expects($this->once())
                ->method('createToken')
                ->will($this->returnValue($refreshToken));
        }

        $authorizationServer = $this->createMock(AuthorizationServer::class);
        $authorizationServer->expects($this->once())
            ->method('hasGrant')
            ->with(RefreshTokenGrant::GRANT_TYPE)
            ->will($this->returnValue($hasRefreshGrant));

        $this->grant = new AuthorizationGrant(
            $this->authorizationCodeService,
            $this->accessTokenService,
            $this->refreshTokenService
        );
        $this->grant->setAuthorizationServer($authorizationServer);

        $response = $this->grant->createTokenResponse($request, $client, $owner);

        $body = json_decode((string) $response->getBody(), true);

        $this->assertEquals('azerty_access', $body['access_token']);
        $this->assertEquals('Bearer', $body['token_type']);
        $this->assertEquals(3600, $body['expires_in']);
        $this->assertEquals('read', $body['scope']);
        $this->assertEquals(1, $body['owner_id']);

        if ($hasRefreshGrant) {
            $this->assertEquals('azerty_refresh', $body['refresh_token']);
        }
    }

    private function getValidRefreshToken(?TokenOwnerInterface $owner = null, ?array $scopes = null): RefreshToken
    {
        $validDate = (new DateTimeImmutable('@10000'))->add(new DateInterval('P1D'));
        return RefreshToken::reconstitute([
            'token'     => 'azerty_refresh',
            'owner'     => $owner,
            'client'    => null,
            'scopes'    => $scopes ?? ['read'],
            'expiresAt' => $validDate,
        ]);
    }

    private function getValidAccessToken(?TokenOwnerInterface $owner = null, ?array $scopes = null): AccessToken
    {
        $validDate = (new DateTimeImmutable('@10000'))->add(new DateInterval('PT1H'));
        return AccessToken::reconstitute([
            'token'     => 'azerty_access',
            'owner'     => $owner,
            'client'    => null,
            'scopes'    => $scopes ?? ['read'],
            'expiresAt' => $validDate,
        ]);
    }

    private function getInvalidAuthorizationCode(
        ?string $redirectUri = null,
        ?string $owner = null,
        ?string $client = null,
        ?array $scopes = null
    ): AuthorizationCode {
        $invalidDate = (new DateTimeImmutable('@10000'))->sub(new DateInterval('PT1H'));
        return AuthorizationCode::reconstitute([
            'token'       => 'azerty_auth',
            'owner'       => $owner,
            'client'      => $client,
            'scopes'      => $scopes ?? ['read'],
            'expiresAt'   => $invalidDate,
            'redirectUri' => $redirectUri ?? '',
        ]);
    }

    private function getValidAuthorizationCode(
        ?string $redirectUri = null,
        ?string $owner = null,
        ?Client $client = null,
        ?array $scopes = null
    ): AuthorizationCode {
        $validDate = (new DateTimeImmutable('@10000'))->add(new DateInterval('PT1H'));
        return AuthorizationCode::reconstitute([
            'token'       => 'azerty_auth',
            'owner'       => $owner,
            'client'      => $client,
            'scopes'      => $scopes ?? ['read'],
            'expiresAt'   => $validDate,
            'redirectUri' => $redirectUri ?? '',
        ]);
    }

    public function testMethodGetType(): void
    {
        $this->assertSame('authorization_code', $this->grant->getType());
    }

    public function testMethodGetResponseType(): void
    {
        $this->assertSame('code', $this->grant->getResponseType());
    }

    public function testMethodAllowPublicClients(): void
    {
        $this->assertTrue($this->grant->allowPublicClients());
    }
}
