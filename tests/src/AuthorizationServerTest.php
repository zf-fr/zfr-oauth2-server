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
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Grant\AuthorizationGrant;
use ZfrOAuth2\Server\Grant\ClientCredentialsGrant;
use ZfrOAuth2\Server\Grant\GrantInterface;
use ZfrOAuth2\Server\Grant\PasswordGrant;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\AuthorizationCodeService;
use ZfrOAuth2\Server\Service\ClientService;
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\AuthorizationServer
 */
class AuthorizationServerTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCheckAndGetForGrants()
    {
        $clientService = $this->createMock(ClientService::class);
        $grant         = new PasswordGrant(
            $this->createMock(AccessTokenService::class),
            $this->createMock(RefreshTokenService::class),
            function () {
            }
        );

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $this->assertTrue($authorizationServer->hasGrant(PasswordGrant::GRANT_TYPE));
        $this->assertFalse($authorizationServer->hasGrant(ClientCredentialsGrant::GRANT_TYPE));

        $this->assertSame($grant, $authorizationServer->getGrant(PasswordGrant::GRANT_TYPE));

        $this->expectException(OAuth2Exception::class, null, 'unsupported_grant_type');
        $authorizationServer->getGrant(ClientCredentialsGrant::GRANT_TYPE);
    }

    public function testCanCheckAndGetForResponseType()
    {
        $clientService = $this->createMock(ClientService::class);
        $grant         = new AuthorizationGrant(
            $this->createMock(AuthorizationCodeService::class),
            $this->createMock(AccessTokenService::class),
            $this->createMock(RefreshTokenService::class)
        );

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $this->assertTrue($authorizationServer->hasResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));
        $this->assertFalse($authorizationServer->hasResponseType(ClientCredentialsGrant::GRANT_RESPONSE_TYPE));

        $this->assertSame($grant, $authorizationServer->getResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));

        $this->expectException(OAuth2Exception::class, null, 'unsupported_response_type');
        $authorizationServer->getResponseType(ClientCredentialsGrant::GRANT_RESPONSE_TYPE);
    }

    public function testThrowExceptionIfNoResponseType()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getQueryParams')->willReturn([]);

        $clientService       = $this->createMock(ClientService::class);
        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleAuthorizationRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    /**
     * Case for grant types that allow for public clients (such as implicit or authorization code), but don't provide
     * a client id
     */
    public function testThrowExceptionIfNoClientIdAtHandleAuthorisationRequests()
    {
        $authorizationGrant = $this->createMock(AuthorizationGrant::class);

        $authorizationGrant->expects($this->any())->method('getType')->willReturn(AuthorizationGrant::GRANT_TYPE);
        $authorizationGrant->expects($this->any())->method('getResponseType')->willReturn(AuthorizationGrant::GRANT_RESPONSE_TYPE);
        $authorizationGrant->expects($this->any())->method('allowPublicClients')->willReturn(true);

        $request = $this->createMock(ServerRequestInterface::class);

        // we will fake the AuthorizationGrant type
        $request->expects($this->once())->method('getQueryParams')->with()->willReturn(['response_type' => 'code']);

        // use POST vars
        $request->expects($this->once())->method('getParsedBody')->willReturn(['client_secret' => 'clientsecret']);
        $clientService       = $this->createMock(ClientService::class);
        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$authorizationGrant], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleAuthorizationRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionIfNoGrantType()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn([]);

        $clientService       = $this->createMock(ClientService::class);

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionIfPrivateClientDoesNotHaveSecret()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->exactly(2))->method('getParsedBody')->willReturn(['grant_type' => 'client_credentials']);

        $grant = new ClientCredentialsGrant($this->createMock(AccessTokenService::class));

        $clientService       = $this->createMock(ClientService::class);

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionForIncorrectSecret()
    {
        $grant = $this->createMock(ClientCredentialsGrant::class);

        $grant->expects($this->any())->method('getType')->willReturn(ClientCredentialsGrant::GRANT_TYPE);
        $grant->expects($this->any())->method('getResponseType')->willReturn(ClientCredentialsGrant::GRANT_RESPONSE_TYPE);
        $grant->expects($this->once())->method('allowPublicClients')->willReturn(false);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->exactly(1))->method('getParsedBody')->willReturn(['grant_type' => 'client_credentials']);
        $request->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(true);

        $request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Authorization Y2xpZW50aWQ6Y2xpZW50c2VjcmV0');

        $client = Client::reconstitute([
            'id'           => 'clientid',
            'name'         => 'clientname',
            'secret'       => '$2y$10$ixK8D7rBvEPkX0.d3e93h.lb3wufbavWmIyX0zK1FhP3fGp.rIK1u', // hash of 'incorrectclientsecret'
            'redirectUris' => ['http://example.com']
        ]);

        $clientService = $this->createMock(ClientService::class);
        $clientService->expects($this->once())->method('getClient')->with('clientid')->willReturn($client);

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);
        $response = $authorizationServer->handleTokenRequest($request);

        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
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
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects(static::once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->createMock(ClientService::class);
        $grant               = $this->createMock(GrantInterface::class);

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        if ($tokenType === 'access_token') {
            $accessTokenService->expects($this->once())->method('getToken')->with('abc')->will($this->returnValue(null));
            $accessTokenService->expects($this->never())->method('deleteToken');
        } elseif ($tokenType === 'refresh_token') {
            $refreshTokenService->expects($this->once())->method('getToken')->with('abc')->will($this->returnValue(null));
            $refreshTokenService->expects($this->never())->method('deleteToken');
        }

        $response = $authorizationServer->handleRevocationRequest($request);

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
    }

    /**
     * @dataProvider revocationProvider
     */
    public function testCanRevokeToken($tokenType)
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->createMock(ClientService::class);
        $grant               = $this->createMock(GrantInterface::class);

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        if ($tokenType === 'access_token') {
            $token = AccessToken::reconstitute(['token'=>'abc', 'owner'=>null, 'client'=>null, 'scopes'=>[], 'expiresAt'=>new \DateTimeImmutable()]);

            $accessTokenService->expects($this->once())->method('getToken')->with('abc')->will($this->returnValue($token));
            $accessTokenService->expects($this->once())->method('deleteToken')->with($token);
        } elseif ($tokenType === 'refresh_token') {
            $token = RefreshToken::reconstitute(['token'=>'abc', 'owner'=>null, 'client'=>null, 'scopes'=>[], 'expiresAt'=>new \DateTimeImmutable()]);

            $refreshTokenService->expects($this->once())->method('getToken')->with('abc')->will($this->returnValue($token));
            $refreshTokenService->expects($this->once())->method('deleteToken')->with($token);
        }

        $response = $authorizationServer->handleRevocationRequest($request);

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
    }

    /**
     * @dataProvider revocationProvider
     */
    public function testReturn503IfCannotRevoke($tokenType)
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->createMock(ClientService::class);
        $grant               = $this->createMock(GrantInterface::class);

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        if ($tokenType === 'access_token') {
            $token = AccessToken::reconstitute(['token'=>'abc', 'owner'=>null, 'client'=>null, 'scopes'=>[], 'expiresAt'=>new \DateTimeImmutable()]);

            $accessTokenService->expects($this->once())->method('getToken')->with('abc')->will($this->returnValue($token));
            $accessTokenService->expects($this->once())
                               ->method('deleteToken')
                               ->with($token)
                               ->will($this->throwException(new \RuntimeException()));
        } elseif ($tokenType === 'refresh_token') {
            $token = RefreshToken::reconstitute(['token'=>'abc', 'owner'=>null, 'client'=>null, 'scopes'=>[], 'expiresAt'=>new \DateTimeImmutable()]);

            $refreshTokenService->expects($this->once())->method('getToken')->with('abc')->will($this->returnValue($token));
            $refreshTokenService->expects($this->once())
                                ->method('deleteToken')
                                ->with($token)
                                ->will($this->throwException(new \RuntimeException()));
        }

        $response = $authorizationServer->handleRevocationRequest($request);

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(503, $response->getStatusCode());
    }

    /**
     * Tests two happy paths for the authorization flow
     *
     * @dataProvider dpHandleAuthorizationRequest
     */
    public function testHandleAuthorizationRequest(string $credentialsmethod)
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getQueryParams')->with()->willReturn(['response_type' => 'code']);

        // use ClientCredential from Authorization header
        if ('bearer' === $credentialsmethod) {
            $request->expects($this->once())
                ->method('hasHeader')
                ->with('Authorization')
                ->willReturn(true);

            $request->expects($this->once())
                ->method('getHeaderLine')
                ->with('Authorization')
                ->willReturn('Authorization Y2xpZW50aWQ6Y2xpZW50c2VjcmV0');
        }

        // use ClientCredential from POST vars
        if ('post' === $credentialsmethod) {
            $request->expects($this->once())
                ->method('getParsedBody')
                ->willReturn([
                    'client_id'     => 'clientid',
                    'client_secret' => 'clientsecret',
                ]);
        }

        $authorizationGrant = $this->createMock(AuthorizationGrant::class);

        $authorizationGrant->expects($this->any())->method('getType')->willReturn(AuthorizationGrant::GRANT_TYPE);
        $authorizationGrant->expects($this->any())->method('getResponseType')->willReturn(AuthorizationGrant::GRANT_RESPONSE_TYPE);
        $authorizationGrant->expects($this->any())->method('allowPublicClients')->willReturn(true);

        $client = Client::reconstitute([
            'id'           => 'clientid',
            'name'         => 'clientname',
            'secret'       => 'clientsecret',
            'redirectUris' => ['http://example.com']
        ]);

        $clientService = $this->createMock(ClientService::class);
        $clientService->expects($this->once())->method('getClient')->with('clientid')->willReturn($client);

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$authorizationGrant], $accessTokenService,
            $refreshTokenService);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())
            ->method('withHeader')
            ->with('Content-Type', 'application/json')
            ->willReturn($response);

        $authorizationGrant->expects($this->once())
            ->method('createAuthorizationResponse')
            ->with($request, $client, null)
            ->willReturn($response);

        $authorizationServer->handleAuthorizationRequest($request, null);
    }

    public function dpHandleAuthorizationRequest()
    {
        return [
            ['bearer'], // use bearer for client credentials
            ['post'], // use POST vars for client credentials
        ];
    }

    /**
     * Happy path throught handleTokenRequest
     */
    public function testHandleTokenRequest()
    {
        $grant = $this->createMock(ClientCredentialsGrant::class);

        $grant->expects($this->any())->method('getType')->willReturn(ClientCredentialsGrant::GRANT_TYPE);
        $grant->expects($this->any())->method('getResponseType')->willReturn(ClientCredentialsGrant::GRANT_RESPONSE_TYPE);
        $grant->expects($this->once())->method('allowPublicClients')->willReturn(false);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->at(0))->method('withHeader')->with('Content-Type', 'application/json')->willReturn($response);
        $response->expects($this->at(1))->method('withHeader')->with('Cache-Control', 'no-store')->willReturn($response);
        $response->expects($this->at(2))->method('withHeader')->with('Pragma', 'no-cache')->willReturn($response);


        $grant->expects($this->once())->method('createTokenResponse')->willReturn($response);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->exactly(1))->method('getParsedBody')->willReturn(['grant_type' => 'client_credentials']);
        $request->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(true);

        $request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Authorization Y2xpZW50aWQ6Y2xpZW50c2VjcmV0');

        $client = Client::reconstitute([
            'id'           => 'clientid',
            'name'         => 'clientname',
            'secret'       => '$2y$10$Nhc3Wlyez2lOM3U7vGZIBOIJOi14HxZB7CWEf2ymyIWKrDEs0OCRW', // hash of 'clientsecret'
            'redirectUris' => ['http://example.com']
        ]);
        $clientService = $this->createMock(ClientService::class);
        $clientService->expects($this->once())->method('getClient')->with('clientid')->willReturn($client);

        $accessTokenService  = $this->createMock(AccessTokenService::class);
        $refreshTokenService = $this->createMock(RefreshTokenService::class);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $authorizationServer->handleTokenRequest($request);
    }
}
