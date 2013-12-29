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

use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use ZfrOAuth2\Server\Entity\AccessToken;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Service\AccessTokenService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @cover \ZfrOAuth2\Server\Service\AccessTokenService
 */
class AccessTokenServiceTest extends \PHPUnit_Framework_TestCase
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
     * @var AccessTokenService
     */
    protected $tokenService;

    public function setUp()
    {
        $this->objectManager   = $this->getMock('Doctrine\Common\Persistence\ObjectManager');
        $this->tokenRepository = $this->getMock('ZfrOAuth2Test\Server\Asset\SelectableObjectRepository');
        $this->tokenService    = new AccessTokenService($this->objectManager, $this->tokenRepository);
    }

    public function testGettersAndSetters()
    {
        $this->assertEquals(3600, $this->tokenService->getTokenTTL());
        $this->tokenService->setTokenTTL(1000);
        $this->assertEquals(1000, $this->tokenService->getTokenTTL());
    }

    public function testCanGetToken()
    {
        $token = new AccessToken();

        $this->tokenRepository->expects($this->once())
                              ->method('find')
                              ->with('token')
                              ->will($this->returnValue($token));

        $this->assertSame($token, $this->tokenService->getToken('token'));
    }

    public function testCanDeleteToken()
    {
        $token = new AccessToken();
        $this->objectManager->expects($this->once())->method('remove')->with($token);

        $this->tokenService->deleteToken($token);
    }

    public function testCanDeleteExpiredTokens()
    {
        $expiredToken  = new AccessToken();
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
                            ->with($this->isInstanceOf('ZfrOAuth2\Server\Entity\AccessToken'));

        $token = $this->tokenService->createToken($client, $owner);

        $this->assertInstanceOf('ZfrOAuth2\Server\Entity\AccessToken', $token);
        $this->assertEquals(40, strlen($token->getToken()));
        $this->assertEquals('read', $token->getScope());
        $this->assertSame($owner, $token->getOwner());
        $this->assertSame($client, $token->getClient());
        $this->assertFalse($token->isExpired());
    }
}
