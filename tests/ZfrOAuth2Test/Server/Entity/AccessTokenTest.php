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

namespace ZfrOAuth2Test\Server\Entity;

use DateInterval;
use DateTime;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\Scope;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Entity\AbstractToken
 * @covers \ZfrOAuth2\Server\Entity\AccessToken
 */
class AccessTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testGettersAndSetters()
    {
        $owner     = $this->getMock('ZfrOAuth2\Server\Entity\TokenOwnerInterface');
        $client    = new Client();
        $expiresAt = new DateTime();

        $accessToken = new AccessToken();
        $accessToken->setToken('token');
        $accessToken->setScopes(['scope1', 'scope2']);
        $accessToken->setClient($client);
        $accessToken->setExpiresAt($expiresAt);
        $accessToken->setOwner($owner);

        $this->assertEquals('token', $accessToken->getToken());
        $this->assertCount(2, $accessToken->getScopes());
        $this->assertTrue($accessToken->matchScopes('scope1'));
        $this->assertFalse($accessToken->matchScopes('scope3'));
        $this->assertSame($client, $accessToken->getClient());
        $this->assertEquals($expiresAt, $accessToken->getExpiresAt());
        $this->assertSame($owner, $accessToken->getOwner());
    }

    public function testCanSetScopesFromString()
    {
        $scopes = 'foo bar';

        $accessToken = new AccessToken();
        $accessToken->setScopes($scopes);

        $this->assertCount(2, $accessToken->getScopes());
    }

    public function testCanSetScopesFromInstances()
    {
        $scope = new Scope();
        $scope->setName('bar');

        $accessToken = new AccessToken();
        $accessToken->setScopes([$scope]);

        $this->assertCount(1, $accessToken->getScopes());
    }

    public function testCalculateExpiresIn()
    {
        $expiresAt = new DateTime();
        $expiresAt->add(new DateInterval('PT60S'));

        $accessToken = new AccessToken();
        $accessToken->setExpiresAt($expiresAt);

        $this->assertFalse($accessToken->isExpired());
        $this->assertEquals(60, $accessToken->getExpiresIn());
    }

    public function testCanCheckIfATokenIsExpired()
    {
        $expiresAt = new DateTime();
        $expiresAt->sub(new DateInterval('PT60S'));

        $accessToken = new AccessToken();
        $accessToken->setExpiresAt($expiresAt);

        $this->assertTrue($accessToken->isExpired());
    }
}
