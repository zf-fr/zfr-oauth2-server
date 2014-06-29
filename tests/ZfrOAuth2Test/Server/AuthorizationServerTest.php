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

use Zend\Http\Request as HttpRequest;
use Zend\Http\Response as HttpResponse;
use Zend\Stdlib\Parameters;
use ZfrOAuth2\Server\AuthorizationServer;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Event\TokenEvent;
use ZfrOAuth2\Server\Grant\AuthorizationGrant;
use ZfrOAuth2\Server\Grant\ClientCredentialsGrant;
use ZfrOAuth2\Server\Grant\PasswordGrant;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\AuthorizationServer
 */
class AuthorizationServerTest extends \PHPUnit_Framework_TestCase
{
    public function testCanCheckAndGetForGrants()
    {
        $clientService = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $grant         = new PasswordGrant(
            $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false),
            $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false),
            function() {}
        );

        $authorizationServer = new AuthorizationServer($clientService, [$grant]);

        $this->assertTrue($authorizationServer->hasGrant('password'));
        $this->assertFalse($authorizationServer->hasGrant('client_credentials'));

        $this->assertSame($grant, $authorizationServer->getGrant('password'));

        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'unsupported_grant_type');
        $authorizationServer->getGrant('client_credentials');
    }

    public function testCanCheckAndGetForResponseType()
    {
        $clientService = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $grant         = new AuthorizationGrant(
            $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false),
            $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false),
            $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false)
        );

        $authorizationServer = new AuthorizationServer($clientService, [$grant]);

        $this->assertTrue($authorizationServer->hasResponseType('code'));
        $this->assertFalse($authorizationServer->hasResponseType(null));

        $this->assertSame($grant, $authorizationServer->getResponseType('code'));

        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'unsupported_response_type');
        $authorizationServer->getResponseType(null);
    }

    public function testThrowExceptionIfNoResponseType()
    {
        $request = new HttpRequest();

        $clientService       = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $authorizationServer = new AuthorizationServer($clientService, []);

        $response = $authorizationServer->handleAuthorizationRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionIfNoGrantType()
    {
        $request = new HttpRequest();

        $clientService       = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $authorizationServer = new AuthorizationServer($clientService, []);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testThrowExceptionIfPrivateClientDoesNotHaveSecret()
    {
        $request = new HttpRequest();
        $request->getPost()->set('grant_type', 'client_credentials');

        $grant = new ClientCredentialsGrant($this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false));

        $clientService       = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $authorizationServer = new AuthorizationServer($clientService, [$grant]);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }

    public function testCanTriggerCreatedEventForToken()
    {
        $request = new HttpRequest();
        $request->setPost(new Parameters(['grant_type' => 'grantType']));

        $clientService       = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $grant               = $this->getMock('ZfrOAuth2\Server\Grant\GrantInterface');

        $grant->expects($this->once())->method('allowPublicClients')->will($this->returnValue(true));
        $grant->expects($this->once())->method('getType')->will($this->returnValue('grantType'));

        $authorizationServer = new AuthorizationServer($clientService, [$grant]);

        $accessToken = new AccessToken();

        $response = new HttpResponse();
        $response->setContent(json_encode(['foo' => 'bar']));
        $response->setMetadata('accessToken', $accessToken);

        $grant->expects($this->once())->method('createTokenResponse')->will($this->returnValue($response));

        $eventManager = $this->getMock('Zend\EventManager\EventManagerInterface');
        $authorizationServer->setEventManager($eventManager);

        $response->setMetadata('accessToken', $accessToken);

        $eventManager->expects($this->once())
            ->method('trigger')
            ->with(TokenEvent::EVENT_TOKEN_CREATED, $this->callback(
                function(TokenEvent $event) use ($request, $accessToken) {
                    $this->assertSame($request, $event->getRequest());
                    $this->assertSame($accessToken, $event->getAccessToken());
                    $this->assertEquals(['foo' => 'bar'], $event->getResponseBody());

                    return true;
                }));

        $response = $authorizationServer->handleTokenRequest($request);

        // First check that headers are properly added
        $this->assertTrue($response->getHeaders()->has('Content-Type'));
        $this->assertTrue($response->getHeaders()->has('Cache-Control'));
        $this->assertTrue($response->getHeaders()->has('Pragma'));

        $this->assertEquals('application/json', $response->getHeaders()->get('Content-Type')->getFieldValue());
        $this->assertEquals('no-store', $response->getHeaders()->get('Cache-Control')->getFieldValue());
        $this->assertEquals('no-cache', $response->getHeaders()->get('Pragma')->getFieldValue());
    }

    public function testCanTriggerFailedEventForToken()
    {
        $request = new HttpRequest();
        $request->setPost(new Parameters(['grant_type' => 'grantType']));

        $clientService       = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $grant               = $this->getMock('ZfrOAuth2\Server\Grant\GrantInterface');

        $grant->expects($this->once())->method('allowPublicClients')->will($this->returnValue(true));
        $grant->expects($this->once())->method('getType')->will($this->returnValue('grantType'));

        $authorizationServer = new AuthorizationServer($clientService, [$grant]);

        $response = new HttpResponse();
        $response->setStatusCode(400);
        $response->setContent(json_encode(['foo' => 'bar']));

        $grant->expects($this->once())->method('createTokenResponse')->will($this->returnValue($response));

        $eventManager = $this->getMock('Zend\EventManager\EventManagerInterface');
        $authorizationServer->setEventManager($eventManager);

        $eventManager->expects($this->once())
            ->method('trigger')
            ->with(TokenEvent::EVENT_TOKEN_FAILED, $this->callback(
                function(TokenEvent $event) use ($request) {
                    $this->assertSame($request, $event->getRequest());
                    $this->assertNull($event->getAccessToken());
                    $this->assertEquals(['foo' => 'bar'], $event->getResponseBody());

                    return true;
                }));

        $response = $authorizationServer->handleTokenRequest($request);

        // First check that headers are properly added
        $this->assertTrue($response->getHeaders()->has('Content-Type'));
        $this->assertTrue($response->getHeaders()->has('Cache-Control'));
        $this->assertTrue($response->getHeaders()->has('Pragma'));

        $this->assertEquals('application/json', $response->getHeaders()->get('Content-Type')->getFieldValue());
        $this->assertEquals('no-store', $response->getHeaders()->get('Cache-Control')->getFieldValue());
        $this->assertEquals('no-cache', $response->getHeaders()->get('Pragma')->getFieldValue());
    }
}
