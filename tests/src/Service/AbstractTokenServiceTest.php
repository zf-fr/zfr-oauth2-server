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

use PHPUnit\Framework\TestCase;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Repository\AccessTokenRepositoryInterface;
use ZfrOAuth2\Server\Service\AbstractTokenService;
use ZfrOAuth2\Server\Service\AccessTokenService;
use ZfrOAuth2\Server\Service\ScopeService;
use ZfrOAuth2Test\Server\Asset\SomeToken;

/**
 * @author  Bas Kamer <baskamer@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Service\AbstractTokenService
 */
class AbstractTokenServiceTest extends TestCase
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    protected $tokenRepository;

    /**
     * @var ScopeService
     */
    protected $scopeService;

    /**
     * @var AccessTokenService
     */
    protected $abstractTokenService;

    public function setUp()
    {
        $this->tokenRepository      = $this->createMock(AccessTokenRepositoryInterface::class);
        $this->scopeService         = $this->createMock(ScopeService::class);
        $this->abstractTokenService = $this->getMockForAbstractClass(AbstractTokenService::class, [
            $this->tokenRepository,
            $this->scopeService,
            ServerOptions::fromArray()
        ]);
    }

    public function testCanCallGetTokenWithTokenFound()
    {
        $token = SomeToken::reconstitute(
            [
                'token'     => 'token',
                'owner'     => $this->createMock(TokenOwnerInterface::class),
                'client'    => $this->createMock(Client::class),
                'expiresAt' => new \DateTimeImmutable(),
                'scopes'    => [],
            ]
        );

        $this->tokenRepository->expects($this->once())
            ->method('findByToken')
            ->with('token')
            ->will($this->returnValue($token));

        $result = $this->abstractTokenService->getToken('token');

        $this->assertSame($token, $result);
    }

    public function testCanCallGetTokenButRetrievedTokenHashDiffers()
    {
        $token = SomeToken::reconstitute(
            [
                'token'     => 'token',
                'owner'     => $this->createMock(TokenOwnerInterface::class),
                'client'    => $this->createMock(Client::class),
                'expiresAt' => new \DateTimeImmutable(),
                'scopes'    => [],
            ]
        );

        $this->tokenRepository->expects($this->once())
            ->method('findByToken')
            ->with('atoken')
            ->will($this->returnValue($token));

        $this->assertNull($this->abstractTokenService->getToken('atoken'));
    }

    public function testGetTokenReturnNullOnTokenNotFound()
    {
        $this->tokenRepository
            ->expects($this->once())
            ->method('findByToken')
            ->with('token');

        $this->assertNull($this->abstractTokenService->getToken('token'));
    }

    public function testCanDeleteToken()
    {
        $token = SomeToken::reconstitute(
            [
                'token'     => 'token',
                'owner'     => $this->createMock(TokenOwnerInterface::class),
                'client'    => $this->createMock(Client::class),
                'expiresAt' => new \DateTimeImmutable(),
                'scopes'    => [],
            ]
        );

        $this->tokenRepository->expects($this->once())
            ->method('deleteToken')
            ->with($token);

        $this->abstractTokenService->deleteToken($token);
    }

    /**
     * @dataProvider dpCanValidateScopes
     */
    public function testCanValidateScopes(array $registeredScopes, array $scopes, bool $expectsException)
    {
        $this->scopeService->expects($this->once())
            ->method('getAll')
            ->willReturn($registeredScopes);

        if ($expectsException) {
            $this->expectException(OAuth2Exception::class);
            $this->expectExceptionCode('invalid_scope');
            $this->expectExceptionMessage('Some scope(s) do not exist: scope_1, scope_3');
        }

        // calling protected method from abstract scope service
        $protectedBound = (function ($token) {
            return $this->validateTokenScopes($token);
        })->bindTo($this->abstractTokenService, $this->abstractTokenService);

        $protectedBound($scopes);
    }

    public function dpCanValidateScopes()
    {
        return [
            [
                ['scope_1', 'scope_2', 'scope_3'],
                [],
                false
            ],
            [
                ['scope_2'],
                ['scope_1', 'scope_2', 'scope_3'],
                true
            ],
        ];
    }
}
