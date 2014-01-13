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
use ZfrOAuth2\Server\AuthorizationServer;
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
        $grant         = $this->getMock('ZfrOAuth2\Server\Grant\PasswordGrant', [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant]);

        $this->assertTrue($authorizationServer->hasGrant(PasswordGrant::GRANT_TYPE));
        $this->assertFalse($authorizationServer->hasGrant(ClientCredentialsGrant::GRANT_TYPE));

        $this->assertSame($grant, $authorizationServer->getGrant(PasswordGrant::GRANT_TYPE));

        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'unsupported_grant_type');
        $authorizationServer->getGrant(ClientCredentialsGrant::GRANT_TYPE);
    }

    public function testCanCheckAndGetForResponseType()
    {
        $clientService = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $grant         = $this->getMock('ZfrOAuth2\Server\Grant\AuthorizationGrant', [], [], '', false);

        $authorizationServer = new AuthorizationServer($clientService, [$grant]);

        $this->assertTrue($authorizationServer->hasResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));
        $this->assertFalse($authorizationServer->hasResponseType(ClientCredentialsGrant::GRANT_RESPONSE_TYPE));

        $this->assertSame($grant, $authorizationServer->getResponseType(AuthorizationGrant::GRANT_RESPONSE_TYPE));

        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'unsupported_response_type');
        $authorizationServer->getResponseType(ClientCredentialsGrant::GRANT_RESPONSE_TYPE);
    }

    public function testCanCreateErrorMessages()
    {
        // We are going to use an unusual HTTP verb so that it triggers an exception
        $request = new HttpRequest();
        $request->setMethod('PATCH');

        $clientService       = $this->getMock('ZfrOAuth2\Server\Service\ClientService', [], [], '', false);
        $authorizationServer = new AuthorizationServer($clientService, []);

        $response = $authorizationServer->handleTokenRequest($request);
        $body     = json_decode($response->getBody(), true);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('error_description', $body);
    }
}
