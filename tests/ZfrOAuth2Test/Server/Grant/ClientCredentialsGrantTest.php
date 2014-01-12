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
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Grant\ClientCredentialsGrant;
use ZfrOAuth2\Server\Service\TokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Grant\ClientCredentialsGrant
 */
class ClientCredentialsGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var TokenService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $tokenService;

    /**
     * @var ClientCredentialsGrant
     */
    protected $grant;

    public function setUp()
    {
        $this->tokenService = $this->getMock('ZfrOAuth2\Server\Service\TokenService', [], [], '', false);
        $this->grant = new ClientCredentialsGrant($this->tokenService);
    }

    public function testAssertDoesNotImplementAuthorization()
    {
        $this->setExpectedException('ZfrOAuth2\Server\Exception\OAuth2Exception', null, 'invalid_request');
        $this->grant->createAuthorizationResponse(new HttpRequest(), new Client());
    }

    public function testCanCreateTokenResponse()
    {
        $request = new HttpRequest();

        $client  = new Client();
        $owner   = $this->getMock('ZfrOAuth2\Server\Entity\TokenOwnerInterface');
        $owner->expects($this->once())->method('getTokenOwnerId')->will($this->returnValue(1));

        $token = new AccessToken();
        $token->setToken('azerty');
        $token->setOwner($owner);
        $token->setExpiresAt((new DateTime())->add(new DateInterval('PT1H')));

        $this->tokenService->expects($this->once())->method('createToken')->will($this->returnValue($token));

        $response = $this->grant->createTokenResponse($request, $client, $owner);

        $body = json_decode($response->getContent(), true);

        $this->assertEquals('azerty', $body['access_token']);
        $this->assertEquals('Bearer', $body['token_type']);
        $this->assertEquals(3600, $body['expires_in']);
        $this->assertEquals(1, $body['owner_id']);
    }
}
