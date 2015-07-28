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
use Zend\EventManager\EventManagerInterface;
use ZfrOAuth2\Server\AuthorizationServer;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Event\TokenEvent;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Grant\AuthorizationGrant;
use ZfrOAuth2\Server\Grant\ClientCredentialsGrant;
use ZfrOAuth2\Server\Grant\GrantInterface;
use ZfrOAuth2\Server\Grant\PasswordGrant;
use ZfrOAuth2\Server\Service\ClientService;
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
            $this->getMock(TokenService::class, [], [], '', false),
            $this->getMock(TokenService::class, [], [], '', false),
            function() {}
        );

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $this->assertTrue($authorizationServer->hasGrant(PasswordGrant::GRANT_TYPE));
        $this->assertFalse($authorizationServer->hasGrant(ClientCredentialsGrant::GRANT_TYPE));

        $this->assertSame($grant, $authorizationServer->getGrant(PasswordGrant::GRANT_TYPE));

        $this->setExpectedException(OAuth2Exception::class, null, 'unsupported_grant_type');
        $authorizationServer->getGrant(ClientCredentialsGrant::GRANT_TYPE);
    }

    public function testCanCheckAndGetForResponseType()
    {
        $clientService = $this->getMock(ClientService::class, [], [], '', false);
        $grant         = new AuthorizationGrant(
            $this->getMock(TokenService::class, [], [], '', false),
            $this->getMock(TokenService::class, [], [], '', false),
            $this->getMock(TokenService::class, [], [], '', false)
        );

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $this->assertTrue($authorizationServer->hasResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));
        $this->assertFalse($authorizationServer->hasResponseType(ClientCredentialsGrant::GRANT_RESPONSE_TYPE));

        $this->assertSame($grant, $authorizationServer->getResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));

        $this->setExpectedException(OAuth2Exception::class, null, 'unsupported_response_type');
        $authorizationServer->getResponseType(ClientCredentialsGrant::GRANT_RESPONSE_TYPE);
    }

    public function testThrowExceptionIfNoResponseType()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getQueryParams')->willReturn([]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleAuthorizationRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionIfNoGrantType()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn([]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionIfPrivateClientDoesNotHaveSecret()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->exactly(2))->method('getParsedBody')->willReturn(['grant_type' => 'client_credentials']);

        $grant = new ClientCredentialsGrant($this->getMock(TokenService::class, [], [], '', false));

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testCanTriggerCreatedEventForToken()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->exactly(2))->method('getParsedBody')->willReturn(['grant_type' => 'grantType']);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $grant->expects($this->once())->method('allowPublicClients')->will($this->returnValue(true));
        $grant->expects($this->once())->method('getType')->will($this->returnValue('grantType'));

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $response = $this->getMock(ResponseInterface::class);
        $response->expects($this->at(0))->method('withAddedHeader')->with('Content-Type', 'application/json')->willReturnSelf();
        $response->expects($this->at(1))->method('withAddedHeader')->with('Cache-Control', 'no-store')->willReturnSelf();
        $response->expects($this->at(2))->method('withAddedHeader')->with('Pragma', 'no-cache')->willReturnSelf();
        $response->expects($this->at(3))->method('getStatusCode')->willReturn(200);

        $grant->expects($this->once())->method('createTokenResponse')->will($this->returnValue($response));

        $eventManager = $this->getMock(EventManagerInterface::class);
        $authorizationServer->setEventManager($eventManager);

        $eventManager->expects($this->once())
            ->method('trigger')
            ->with(TokenEvent::EVENT_TOKEN_CREATED, $this->callback(
                function(TokenEvent $event) use ($request, $response) {
                    $this->assertSame($request, $event->getRequest());
                    $this->assertSame($response, $event->getResponse());

                    return true;
                }));

        $authorizationServer->handleTokenRequest($request);
    }

    public function testCanTriggerFailedEventForToken()
    {
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->exactly(2))->method('getParsedBody')->willReturn(['grant_type' => 'grantType']);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $grant->expects($this->once())->method('allowPublicClients')->will($this->returnValue(true));
        $grant->expects($this->once())->method('getType')->will($this->returnValue('grantType'));

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $response = $this->getMock(ResponseInterface::class);
        $response->expects($this->at(0))->method('withAddedHeader')->with('Content-Type', 'application/json')->willReturnSelf();
        $response->expects($this->at(1))->method('withAddedHeader')->with('Cache-Control', 'no-store')->willReturnSelf();
        $response->expects($this->at(2))->method('withAddedHeader')->with('Pragma', 'no-cache')->willReturnSelf();
        $response->expects($this->at(3))->method('getStatusCode')->willReturn(400);

        $grant->expects($this->once())->method('createTokenResponse')->will($this->returnValue($response));

        $eventManager = $this->getMock(EventManagerInterface::class);
        $authorizationServer->setEventManager($eventManager);

        $eventManager->expects($this->once())
            ->method('trigger')
            ->with(TokenEvent::EVENT_TOKEN_FAILED, $this->callback(
                function(TokenEvent $event) use ($request, $response) {
                    $this->assertSame($request, $event->getRequest());
                    $this->assertSame($response, $event->getResponse());

                    return true;
                }));

        $authorizationServer->handleTokenRequest($request);
    }

    public function testTriggerExceptionIfTokenIsNotPresentForRevocation()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'invalid_request');

        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn([]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $authorizationServer->handleRevocationRequest($request);
    }

    public function testTriggerExceptionIfTokenHintIsInvalidForRevocation()
    {
        $this->setExpectedException(OAuth2Exception::class, null, 'unsupported_token_type');

        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => 'invalid']);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        $authorizationServer->handleRevocationRequest($request);
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
        $request->expects($this->once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

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
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        if ($tokenType === 'access_token') {
            $token = new AccessToken();

            $accessTokenService->expects($this->once())->method('getToken')->with('abc')->will($this->returnValue($token));
            $accessTokenService->expects($this->once())->method('deleteToken')->with($token);
        } elseif ($tokenType === 'refresh_token') {
            $token = new RefreshToken();

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
        $request = $this->getMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getParsedBody')->willReturn(['token' => 'abc', 'token_type_hint' => $tokenType]);

        $clientService       = $this->getMock(ClientService::class, [], [], '', false);
        $grant               = $this->getMock(GrantInterface::class);

        $accessTokenService  = $this->getMock(TokenService::class, [], [], '', false);
        $refreshTokenService = $this->getMock(TokenService::class, [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant], $accessTokenService, $refreshTokenService);

        if ($tokenType === 'access_token') {
            $token = new AccessToken();

            $accessTokenService->expects($this->once())->method('getToken')->with('abc')->will($this->returnValue($token));
            $accessTokenService->expects($this->once())
                               ->method('deleteToken')
                               ->with($token)
                               ->will($this->throwException(new \RuntimeException()));
        } elseif ($tokenType === 'refresh_token') {
            $token = new RefreshToken();

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
}
