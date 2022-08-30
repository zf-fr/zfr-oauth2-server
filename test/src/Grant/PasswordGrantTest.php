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
use ZfrOAuth2\Server\Grant\PasswordGrant;
use ZfrOAuth2\Server\Grant\RefreshTokenGrant;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

use function json_decode;

/**
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Grant\PasswordGrant
 */
class PasswordGrantTest extends TestCase
{
    use PHPMock;

    /** @var AccessTokenService|MockObject */
    protected $accessTokenService;

    /** @var RefreshTokenService|MockObject */
    protected $refreshTokenService;

    /** @var callable */
    protected $callback;

    /** @var PasswordGrant */
    protected $grant;

    public function setUp(): void
    {
        $this->accessTokenService  = $this->createMock(AccessTokenService::class);
        $this->refreshTokenService = $this->createMock(RefreshTokenService::class);

        $callable    = function () {
        };
        $this->grant = new PasswordGrant($this->accessTokenService, $this->refreshTokenService, $callable);
    }

    public function tearDown(): void
    {
        Carbon::setTestNow();
    }

    public function testAssertDoesNotImplementAuthorization(): void
    {
        $this->expectException(OAuth2Exception::class, null, 'invalid_request');
        $this->grant->createAuthorizationResponse(
            $this->createMock(ServerRequestInterface::class),
            Client::createNewClient('id', 'http://www.example.com')
        );
    }

    public function testAssertInvalidIfNoUsernameNorPasswordIsFound(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn([]);

        $this->expectException(OAuth2Exception::class, null, 'invalid_request');
        $this->grant->createTokenResponse($request, Client::createNewClient('id', 'http://www.example.com'));
    }

    public function testAssertInvalidIfWrongCredentials(): void
    {
        $this->expectException(OAuth2Exception::class, null, 'access_denied');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['username' => 'michael', 'password' => 'azerty']);

        $callable = function ($username, $password) {
            $this->assertEquals('michael', $username);
            $this->assertEquals('azerty', $password);

            return false;
        };

        $this->grant = new PasswordGrant($this->accessTokenService, $this->refreshTokenService, $callable);

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
    public function testCanCreateTokenResponse(bool $hasRefreshGrant)
    {
        Carbon::setTestNow('1970-01-01 02:46:40');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['username' => 'michael', 'password' => 'azerty', 'scope' => 'read']);

        $owner = $this->createMock(TokenOwnerInterface::class);
        $owner->expects($this->once())
            ->method('getTokenOwnerId')
            ->will($this->returnValue(1));

        $callable = function ($username, $password) use ($owner) {
            return $owner;
        };

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

        $this->grant = new PasswordGrant($this->accessTokenService, $this->refreshTokenService, $callable);
        $this->grant->setAuthorizationServer($authorizationServer);

        $response = $this->grant->createTokenResponse(
            $request,
            Client::createNewClient('id', 'http://www.example.com')
        );

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

    public function testMethodGetType(): void
    {
        $this->assertSame('password', $this->grant->getType());
    }

    public function testMethodGetResponseType(): void
    {
        $this->assertSame('', $this->grant->getResponseType());
    }

    public function testMethodAllowPublicClients(): void
    {
        $this->assertTrue($this->grant->allowPublicClients());
    }
}
