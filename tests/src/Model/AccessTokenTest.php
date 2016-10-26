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

namespace ZfrOAuth2Test\Server\Model;

use DateTimeImmutable;
use DateTimeInterface;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\Scope;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Model\AbstractToken
 * @covers  \ZfrOAuth2\Server\Model\AccessToken
 */
class AccessTokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider providerGenerateNewAccessToken
     */
    public function testGenerateNewAccessToken($ttl, $owner, $client, $scopes)
    {
        /** @var AccessToken $accessToken */
        $accessToken = AccessToken::createNewAccessToken($ttl, $owner, $client, $scopes);

        $expiresAt = (new DateTimeImmutable())->modify("+$ttl seconds");

        $this->assertNotEmpty($accessToken->getToken());
        $this->assertEquals(40, strlen($accessToken->getToken()));
        $this->assertCount(count($scopes), $accessToken->getScopes());
        $this->assertSame($client, $accessToken->getClient());
        $this->assertEquals($expiresAt, $accessToken->getExpiresAt());
        $this->assertSame($owner, $accessToken->getOwner());
    }

    public function providerGenerateNewAccessToken()
    {
        return [
            [
                3600,
                $this->createMock(TokenOwnerInterface::class),
                $this->createMock(Client::class),
                ['read', 'write']
            ],
            [
                3600,
                $this->createMock(TokenOwnerInterface::class),
                $this->createMock(Client::class),
                Scope::createNewScope(1, 'read')
            ],
            [3600, null, null, null]
        ];
    }

    /**
     * @dataProvider providerReconstitute
     */
    public function testReconstitute($data)
    {
        /** @var AccessToken $accessToken */
        $accessToken = AccessToken::reconstitute($data);


        $this->assertEquals($data['token'], $accessToken->getToken());
        $this->assertSame($data['owner'], $accessToken->getOwner());
        $this->assertSame($data['client'], $accessToken->getClient());

        if ($data['expiresAt'] instanceof DateTimeInterface) {
            /** @var DateTimeInterface $expiresAt */
            $expiresAt = $data['expiresAt'];
            $this->assertSame($expiresAt->getTimeStamp(), $accessToken->getExpiresAt()->getTimestamp());
        } else {
            $this->assertNull($accessToken->getExpiresAt());
        }

        $this->assertSame($data['scopes'], $accessToken->getScopes());
    }

    public function providerReconstitute()
    {
        return [
            [
                [
                    'token'     => 'token',
                    'owner'     => $this->createMock(TokenOwnerInterface::class),
                    'client'    => $this->createMock(Client::class),
                    'expiresAt' => new DateTimeImmutable(),
                    'scopes'    => ['scope1', 'scope2'],
                ]
            ],
            [ // test set - null values
              [
                  'token'     => 'token',
                  'owner'     => null,
                  'client'    => null,
                  'expiresAt' => null,
                  'scopes'    => [],
              ]
            ],
        ];
    }

    public function testCalculateExpiresIn()
    {
        $accessToken = AccessToken::createNewAccessToken(60);

        $this->assertFalse($accessToken->isExpired());
        $this->assertEquals(60, $accessToken->getExpiresIn());
    }

    public function testCanCheckIfATokenIsExpired()
    {
        $accessToken = AccessToken::createNewAccessToken(-60);

        $this->assertTrue($accessToken->isExpired());
    }

    public function testSupportLongLiveToken()
    {
        $accessToken = AccessToken::createNewAccessToken(60);
        $this->assertFalse($accessToken->isExpired());
    }

    public function testIsValid()
    {
        $accessToken = AccessToken::createNewAccessToken(60, null, null, 'read write');
        $this->assertTrue($accessToken->isValid('read'));

        $accessToken = AccessToken::createNewAccessToken(-60, null, null, 'read write');
        $this->assertFalse($accessToken->isValid('read'));

        $accessToken = AccessToken::createNewAccessToken(60, null, null, 'read write');
        $this->assertFalse($accessToken->isValid('delete'));
    }
}
