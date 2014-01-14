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
use ZfrOAuth2\Server\Entity\AuthorizationCode;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Entity\Scope;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Entity\AbstractToken
 * @covers \ZfrOAuth2\Server\Entity\AuthorizationCode
 */
class AuthorizationCodeTest extends \PHPUnit_Framework_TestCase
{
    public function testGettersAndSetters()
    {
        $owner     = $this->getMock('ZfrOAuth2\Server\Entity\TokenOwnerInterface');
        $client    = new Client();
        $expiresAt = new DateTime();

        $authorizationCode = new AuthorizationCode();
        $authorizationCode->setToken('token');
        $authorizationCode->setScopes(['scope1', 'scope2']);
        $authorizationCode->setClient($client);
        $authorizationCode->setExpiresAt($expiresAt);
        $authorizationCode->setOwner($owner);
        $authorizationCode->setRedirectUri('http://www.example.com');

        $this->assertEquals('token', $authorizationCode->getToken());
        $this->assertCount(2, $authorizationCode->getScopes());
        $this->assertTrue($authorizationCode->matchScopes('scope1'));
        $this->assertFalse($authorizationCode->matchScopes('scope3'));
        $this->assertSame($client, $authorizationCode->getClient());
        $this->assertEquals($expiresAt, $authorizationCode->getExpiresAt());
        $this->assertSame($owner, $authorizationCode->getOwner());
        $this->assertEquals('http://www.example.com', $authorizationCode->getRedirectUri());
    }

    public function testCanSetScopesFromString()
    {
        $scopes = 'foo bar';

        $authorizationCode = new AuthorizationCode();
        $authorizationCode->setScopes($scopes);

        $this->assertCount(2, $authorizationCode->getScopes());
    }

    public function testCanSetScopesFromInstances()
    {
        $scope = new Scope();
        $scope->setName('bar');

        $authorizationCode = new AuthorizationCode();
        $authorizationCode->setScopes([$scope]);

        $this->assertCount(1, $authorizationCode->getScopes());
    }

    public function testCalculateExpiresIn()
    {
        $expiresAt = new DateTime();
        $expiresAt->add(new DateInterval('PT60S'));

        $authorizationCode = new AuthorizationCode();
        $authorizationCode->setExpiresAt($expiresAt);

        $this->assertFalse($authorizationCode->isExpired());
        $this->assertEquals(60, $authorizationCode->getExpiresIn());
    }

    public function testCanCheckIfATokenIsExpired()
    {
        $expiresAt = new DateTime();
        $expiresAt->sub(new DateInterval('PT60S'));

        $authorizationCode = new AuthorizationCode();
        $authorizationCode->setExpiresAt($expiresAt);

        $this->assertTrue($authorizationCode->isExpired());
    }
}
