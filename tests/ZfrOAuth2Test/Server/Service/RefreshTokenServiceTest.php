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

namespace ZfrOAuth2Test\Server\Service;

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use ZfrOAuth2\Server\Entity\RefreshToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Service\RefreshTokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @cover \ZfrOAuth2\Server\Service\RefreshTokenService
 */
class RefreshTokenServiceTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var ObjectManager|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $objectManager;

    /**
     * @var ObjectRepository|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $tokenRepository;

    /**
     * @var RefreshTokenService
     */
    protected $tokenService;

    public function setUp()
    {
        $this->objectManager   = $this->getMock('Doctrine\Common\Persistence\ObjectManager');
        $this->tokenRepository = $this->getMock('ZfrOAuth2Test\Server\Asset\SelectableObjectRepository');
        $this->tokenService    = new RefreshTokenService($this->objectManager, $this->tokenRepository);
    }

    public function testGettersAndSetters()
    {
        $this->assertEquals(604800, $this->tokenService->getTokenTTL());
        $this->tokenService->setTokenTTL(1000);
        $this->assertEquals(1000, $this->tokenService->getTokenTTL());
    }

    public function testCanGetToken()
    {
        $token = new RefreshToken();

        $this->tokenRepository->expects($this->once())
                              ->method('find')
                              ->with('token')
                              ->will($this->returnValue($token));

        $this->assertSame($token, $this->tokenService->getToken('token'));
    }

    public function testCanDeleteToken()
    {
        $token = new RefreshToken();
        $this->objectManager->expects($this->once())->method('remove')->with($token);

        $this->tokenService->deleteToken($token);
    }

    public function testCanDeleteExpiredTokens()
    {
        $expiredToken  = new RefreshToken();
        $expiredTokens = new ArrayCollection([$expiredToken]);

        $this->tokenRepository->expects($this->at(0))
                              ->method('matching')
                              ->with($this->isInstanceOf('Doctrine\Common\Collections\Criteria'))
                              ->will($this->returnValue($expiredTokens));

        $this->tokenRepository->expects($this->at(1))
                              ->method('matching')
                              ->with($this->isInstanceOf('Doctrine\Common\Collections\Criteria'))
                              ->will($this->returnValue(new ArrayCollection()));

        $this->objectManager->expects($this->once())
                            ->method('remove')
                            ->with($expiredToken);

        $this->tokenService->deleteExpiredTokens();
    }

    public function testCanCreateAccessTokenWithoutScope()
    {
        $client = new Client();
        $client->setScope('read');

        $owner = $this->getMock('ZfrOAuth2\Server\Entity\TokenOwnerInterface');

        $this->objectManager->expects($this->once())
                            ->method('persist')
                            ->with($this->isInstanceOf('ZfrOAuth2\Server\Entity\RefreshToken'));

        $token = $this->tokenService->createToken($client, $owner);

        $this->assertInstanceOf('ZfrOAuth2\Server\Entity\RefreshToken', $token);
        $this->assertEquals(40, strlen($token->getToken()));
        $this->assertEquals('read', $token->getScope());
        $this->assertSame($owner, $token->getOwner());
        $this->assertSame($client, $token->getClient());
        $this->assertFalse($token->isExpired());
    }

    public function scopeProvider()
    {
        return [
            // With less permissions
            [
                'client_scope'    => 'read write',
                'token_scope'     => 'read',
                'throw_exception' => false
            ],
            // With same permissions
            [
                'client_scope'    => 'read write',
                'token_scope'     => 'read write',
                'throw_exception' => false
            ],
            // With too much permissions
            [
                'client_scope'    => 'read write',
                'token_scope'     => 'read write delete',
                'throw_exception' => true
            ]
        ];
    }

    /**
     * @dataProvider scopeProvider
     */
    public function testCanCreateAccessTokenWithScope($clientScope, $tokenScope, $throwException)
    {
        if ($throwException) {
            $this->setExpectedException(
                'ZfrOAuth2\Server\Exception\OAuth2Exception',
                'The scope of the token exceeds the scope(s) allowed by the client',
                'invalid_scope'
            );
        }

        $client = new Client();
        $client->setScope($clientScope);

        $owner = $this->getMock('ZfrOAuth2\Server\Entity\TokenOwnerInterface');
        $token = $this->tokenService->createToken($client, $owner, $tokenScope);

        $this->assertEquals($tokenScope, $token->getScope());
    }
}
