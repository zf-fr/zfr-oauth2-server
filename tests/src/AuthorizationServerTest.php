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

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ZfrOAuth2\Server\AuthorizationServer;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Grant\AuthorizationGrant;
use ZfrOAuth2\Server\Grant\ClientCredentialsGrant;
use ZfrOAuth2\Server\Grant\GrantInterface;
use ZfrOAuth2\Server\Grant\PasswordGrant;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\AuthorizationCodeService;
use ZfrOAuth2\Server\Service\ClientService;
use ZfrOAuth2\Server\Service\RefreshTokenService;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\AuthorizationServer
 */
class AuthorizationServerTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCheckAndGetForGrants()
    {
        $clientService = $this->getMock(ClientService::class, [], [], '', false);
        $grant         = new PasswordGrant(
            $this->getMock(AccessTokenService::class, [], [], '', false),
            $this->getMock(RefreshTokenService::class, [], [], '', false),
            function() {}
        );

        $accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        static::assertTrue($authorizationServer->hasGrant(PasswordGrant::GRANT_TYPE));
        static::assertFalse($authorizationServer->hasGrant(ClientCredentialsGrant::GRANT_TYPE));

        static::assertSame($grant, $authorizationServer->getGrant(PasswordGrant::GRANT_TYPE));

        $this->setExpectedException(OAuth2Exception::class, null, 'unsupported_grant_type');
        $authorizationServer->getGrant(ClientCredentialsGrant::GRANT_TYPE);
    }

    public function testCanCheckAndGetForResponseType()
    {
        $clientService = $this->getMock(ClientService::class, [], [], '', false);
        $grant         = new AuthorizationGrant(
            $this->getMock(AuthorizationCodeService::class, [], [], '', false),
            $this->getMock(AccessTokenService::class, [], [], '', false),
            $this->getMock(RefreshTokenService::class, [], [], '', false)
        );

        $accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        static::assertTrue($authorizationServer->hasResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));
        static::assertFalse($authorizationServer->hasResponseType(ClientCredentialsGrant::GRANT_RESPONSE_TYPE));

        static::assertSame($grant, $authorizationServer->getResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));

        $this->setExpectedException(OAuth2Exception::class, null, 'unsupported_response_type');
        $authorizationServer->getResponseType(ClientCredentialsGrant::GRANT_RESPONSE_TYPE);
    }

    public function testThrowExceptionIfNoResponseType()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getQueryParams')->willReturn([]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleAuthorizationRequest($request);
        $body     = json_decode($response->getBody(), true);

        static::assertEquals(400, $response->getStatusCode());
        static::assertArrayHasKey('error', $body);
        static::assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionIfNoGrantType()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn([]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);

        $accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        static::assertEquals(400, $response->getStatusCode());
        static::assertArrayHasKey('error', $body);
        static::assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionIfPrivateClientDoesNotHaveSecret()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects(static::exactly(2))->method('getParsedBody')->willReturn(['grant_type' => 'client_credentials']);

        $grant = new ClientCredentialsGrant($this->getMock(AccessTokenService::class, [], [], '', false));

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);

        $accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        static::assertEquals(400, $response->getStatusCode());
        static::assertArrayHasKey('error', $body);
        static::assertArrayHasKey('error_description', $body);
    }

    public function revocationProvider()
    {
        return [
            ['access_token'],
            ['refresh_token']
        ];
    }

    /**
     * @dataProvider revocationProvider
     */
    public function testCanReturn200IfTokenDoesNotExistForRevocation($tokenType)
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        if ($tokenType === 'access_token') {
            $accessTokenService->expects(static::once())->method('getToken')->with('abc')->will(static::returnValue(null));
            $accessTokenService->expects(static::never())->method('deleteToken');
        } elseif ($tokenType === 'refresh_token') {
            $refreshTokenService->expects(static::once())->method('getToken')->with('abc')->will(static::returnValue(null));
            $refreshTokenService->expects(static::never())->method('deleteToken');
        }

        $response = $authorizationServer->handleRevocationRequest($request);

        static::assertInstanceOf(ResponseInterface::class, $response);
        static::assertEquals(200, $response->getStatusCode());
    }

    /**
     * @dataProvider revocationProvider
     */
    public function testCanRevokeToken($tokenType)
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        if ($tokenType === 'access_token') {
            $token = AccessToken::reconstitute(['token'=>'abc', 'owner'=>null, 'client'=>null, 'scopes'=>[], 'expiresAt'=>new \DateTimeImmutable()]);

            $accessTokenService->expects(static::once())->method('getToken')->with('abc')->will(static::returnValue($token));
            $accessTokenService->expects(static::once())->method('deleteToken')->with($token);
        } elseif ($tokenType === 'refresh_token') {
            $token = RefreshToken::reconstitute(['token'=>'abc', 'owner'=>null, 'client'=>null, 'scopes'=>[], 'expiresAt'=>new \DateTimeImmutable()]);

            $refreshTokenService->expects(static::once())->method('getToken')->with('abc')->will(static::returnValue($token));
            $refreshTokenService->expects(static::once())->method('deleteToken')->with($token);
        }

        $response = $authorizationServer->handleRevocationRequest($request);

        static::assertInstanceOf(ResponseInterface::class, $response);
        static::assertEquals(200, $response->getStatusCode());
    }

    /**
     * @dataProvider revocationProvider
     */
    public function testReturn503IfCannotRevoke($tokenType)
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(AccessTokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(RefreshTokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        if ($tokenType === 'access_token') {
            $token = AccessToken::reconstitute(['token'=>'abc', 'owner'=>null, 'client'=>null, 'scopes'=>[], 'expiresAt'=>new \DateTimeImmutable()]);

            $accessTokenService->expects(static::once())->method('getToken')->with('abc')->will(static::returnValue($token));
            $accessTokenService->expects(static::once())
                               ->method('deleteToken')
                               ->with($token)
                               ->will(static::throwException(new \RuntimeException()));
        } elseif ($tokenType === 'refresh_token') {
            $token = RefreshToken::reconstitute(['token'=>'abc', 'owner'=>null, 'client'=>null, 'scopes'=>[], 'expiresAt'=>new \DateTimeImmutable()]);

            $refreshTokenService->expects(static::once())->method('getToken')->with('abc')->will(static::returnValue($token));
            $refreshTokenService->expects(static::once())
                                ->method('deleteToken')
                                ->with($token)
                                ->will(static::throwException(new \RuntimeException()));
        }

        $response = $authorizationServer->handleRevocationRequest($request);

        static::assertInstanceOf(ResponseInterface::class, $response);
        static::assertEquals(503, $response->getStatusCode());
    }
}
