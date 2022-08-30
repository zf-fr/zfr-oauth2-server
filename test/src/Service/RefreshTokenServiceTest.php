<?php

declare(strict_types=1);

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

use DateTimeImmutable;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Model\Scope;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Repository\RefreshTokenRepositoryInterface;
use ZfrOAuth2\Server\Service\RefreshTokenService;
use ZfrOAuth2\Server\Service\ScopeService;

use function strlen;

/**
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Service\RefreshTokenService
 */
class RefreshTokenServiceTest extends TestCase
{
    /** @var RefreshTokenRepositoryInterface|MockObject */
    protected $tokenRepository;

    /** @var ScopeService|MockObject */
    protected $scopeService;

    /** @var RefreshTokenService */
    protected $tokenService;

    public function setUp(): void
    {
        $this->tokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $this->scopeService    = $this->createMock(ScopeService::class);
        $this->tokenService    = new RefreshTokenService(
            $this->tokenRepository,
            $this->scopeService,
            ServerOptions::fromArray()
        );
    }

    public function testCanGetToken(): void
    {
        $token = AccessToken::reconstitute(
            [
                'token'     => 'token',
                'owner'     => $this->createMock(TokenOwnerInterface::class),
                'client'    => $this->createMock(Client::class),
                'expiresAt' => new DateTimeImmutable(),
                'scopes'    => [],
            ]
        );

        $this->tokenRepository->expects($this->once())
            ->method('findByToken')
            ->with('token')
            ->will($this->returnValue($token));

        $this->assertSame($token, $this->tokenService->getToken('token'));
    }

    public function testGetTokenReturnNullOnTokenNotFound(): void
    {
        $this->tokenRepository
            ->expects($this->once())
            ->method('findByToken')
            ->with('token');

        $this->assertNull($this->tokenService->getToken('token'));
    }

    public function testDoesCaseSensitiveTest(): void
    {
        $token = AccessToken::reconstitute(
            [
                'token'     => 'Token',
                'owner'     => $this->createMock(TokenOwnerInterface::class),
                'client'    => $this->createMock(Client::class),
                'expiresAt' => new DateTimeImmutable(),
                'scopes'    => [],
            ]
        );

        $this->tokenRepository->expects($this->once())
            ->method('findByToken')
            ->with('token')
            ->will($this->returnValue($token));

        $this->assertNull($this->tokenService->getToken('token'));
    }

    public function scopeProvider(): array
    {
        return [
            // With no scope
            [
                'registered_scopes' => ['read', 'write'],
                'client_scopes'     => ['read', 'write'],
                'token_scope'       => [],
                'throw_exception'   => false,
            ],
            // With less permissions
            [
                'registered_scopes' => ['read', 'write'],
                'client_scopes'     => ['read', 'write'],
                'token_scope'       => ['read'],
                'throw_exception'   => false,
            ],
            // With same permissions
            [
                'registered_scopes' => ['read', 'write'],
                'client_scopes'     => ['read', 'write'],
                'token_scope'       => ['read', 'write'],
                'throw_exception'   => false,
            ],
            // With too much permissions
            [
                'registered_scopes' => ['read', 'write'],
                'client_scopes'     => ['read', 'write'],
                'token_scope'       => ['read', 'write', 'delete'],
                'throw_exception'   => true,
            ],
            // With too little scopes on the client
            [
                'registered_scopes' => ['read', 'write'],
                'client_scopes'     => ['read'],
                'token_scope'       => ['write'],
                'throw_exception'   => true,
            ],
        ];
    }

    /**
     * @dataProvider scopeProvider
     */
    public function testCanSaveToken(
        array $registeredScopes,
        array $clientScopes,
        array $tokenScope,
        bool $throwException
    ): void {
        if ($throwException) {
            $this->expectException(OAuth2Exception::class, null, 'invalid_scope');
        }

        $owner  = $this->createMock(TokenOwnerInterface::class);
        $client = $this->createMock(Client::class);

        $client->expects($this->any())
            ->method('getScopes')
            ->will($this->returnValue($clientScopes));

        if (empty($tokenScope)) {
            $this->scopeService->expects($this->once())
                ->method('getDefaultScopes')
                ->will($this->returnValue(['read']));
        }

        if (! $throwException) {
            $this->tokenRepository->expects($this->once())
                ->method('tokenExists')
                ->willReturn(false);

            $this->tokenRepository->expects($this->once())
                ->method('save')
                ->will($this->returnArgument(0));
        }

        $scopes = [];
        foreach ($registeredScopes as $registeredScope) {
            $scopes[] = $registeredScope;
        }

        $this->scopeService->expects($this->any())->method('getAll')->willReturn($scopes);

        $token = $this->tokenService->createToken($owner, $client, $tokenScope);

        $this->assertInstanceOf(RefreshToken::class, $token);
        $this->assertEquals(40, strlen($token->getToken()));

        if (empty($tokenScope)) {
            $this->assertCount(1, $token->getScopes());
        } else {
            $this->assertEquals($tokenScope, $token->getScopes());
        }
    }

    public function testCreateNewTokenUntilOneDoesNotExist(): void
    {
        $this->scopeService->expects($this->once())->method('getDefaultScopes')->will($this->returnValue(['read']));
        $this->scopeService->expects($this->once())->method('getAll')->will($this->returnValue([
            Scope::reconstitute(['id' => 1, 'name' => 'read', 'description' => 'desc', 'isDefault' => false]),
        ]));

        $this->tokenRepository
            ->expects($this->exactly(2))
            ->method('tokenExists')
            ->with($this->isType('string'))
            ->will(
                $this->onConsecutiveCalls(
                    true,
                    false
                )
            );

        $this->tokenRepository
            ->expects($this->once())
            ->method('save')
            ->will($this->returnArgument(0));

        $owner  = $this->createMock(TokenOwnerInterface::class);
        $client = $this->createMock(Client::class);

        $client->expects($this->once())
               ->method('getScopes')
               ->will($this->returnValue(['read']));

        $token = $this->tokenService->createToken($owner, $client, []);
        $this->assertEquals(40, strlen($token->getToken()));
    }
}
