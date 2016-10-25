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

use ZfrOAuth2\Server\Exception\OAuth2Exception;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\AuthorizationCode;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2\Server\Options\ServerOptions;
use ZfrOAuth2\Server\Repository\AuthorizationCodeRepositoryInterface;
use ZfrOAuth2\Server\Service\AuthorizationCodeService;
use ZfrOAuth2\Server\Service\ScopeService;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Service\AuthorizationCodeService
 */
class AuthorizationCodeServiceTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var AuthorizationCodeRepositoryInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $tokenRepository;

    /**
     * @var ScopeService|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $scopeService;

    /**
     * @var AuthorizationCodeService
     */
    protected $tokenService;

    public function setUp()
    {
        $this->tokenRepository = $this->createMock(AuthorizationCodeRepositoryInterface::class);
        $this->scopeService    = $this->createMock(ScopeService::class);
        $this->tokenService    = new AuthorizationCodeService(
            $this->tokenRepository,
            $this->scopeService,
            ServerOptions::fromArray()
        );
    }

    public function testCanGetToken()
    {
        $token = AccessToken::reconstitute(
            [
                'token'     => 'token',
                'owner'     => $this->createMock(TokenOwnerInterface::class),
                'client'    => $this->createMock(Client::class),
                'expiresAt' => new \DateTimeImmutable(),
                'scopes'    => [],
            ]
        );

        $this->tokenRepository->expects(static::once())
            ->method('findByToken')
            ->with('token')
            ->will(static::returnValue($token));

        static::assertSame($token, $this->tokenService->getToken('token'));
    }

    public function testGetTokenReturnNullOnTokenNotFound()
    {
        $this->tokenRepository
            ->expects(static::once())
            ->method('findByToken')
            ->with('token');

        static::assertNull($this->tokenService->getToken('token'));
    }

    public function testDoesCaseSensitiveTest()
    {
        $token = AccessToken::reconstitute(
            [
                'token'     => 'Token',
                'owner'     => $this->createMock(TokenOwnerInterface::class),
                'client'    => $this->createMock(Client::class),
                'expiresAt' => new \DateTimeImmutable(),
                'scopes'    => [],
            ]
        );

        $this->tokenRepository->expects(static::once())
            ->method('findByToken')
            ->with('token')
            ->will(static::returnValue($token));

        static::assertNull($this->tokenService->getToken('token'));
    }

    public function scopeProvider()
    {
        return [
            // With no scope
            [
                'registered_scopes' => ['read', 'write'],
                'token_scope'       => [],
                'throw_exception'   => false
            ],
            // With less permissions
            [
                'registered_scopes' => ['read', 'write'],
                'token_scope'       => ['read'],
                'throw_exception'   => false
            ],
            // With same permissions
            [
                'registered_scopes' => ['read', 'write'],
                'token_scope'       => ['read', 'write'],
                'throw_exception'   => false
            ],
            // With too much permissions
            [
                'registered_scopes' => ['read', 'write'],
                'token_scope'       => ['read', 'write', 'delete'],
                'throw_exception'   => true
            ],
        ];
    }

    /**
     * @dataProvider scopeProvider
     */
    public function testCanSaveToken($registeredScopes, $tokenScope, $throwException)
    {
        if ($throwException) {
            $this->expectException(OAuth2Exception::class, null, 'invalid_scope');
        }

        $owner  = $this->createMock(TokenOwnerInterface::class);
        $client = $this->createMock(Client::class);

        if (empty($tokenScope)) {
            $this->scopeService->expects(static::once())
                ->method('getDefaultScopes')
                ->will(static::returnValue(['read']));
        }

        if (!$throwException) {
            $this->tokenRepository->expects(static::once())
                ->method('tokenExists')
                ->willReturn(false);

            $this->tokenRepository->expects(static::once())
                ->method('save')
                ->will(static::returnArgument(0));
        }

        $scopes = [];
        foreach ($registeredScopes as $registeredScope) {
            $scopes[] = $registeredScope;
        }

        $this->scopeService->expects(static::any())->method('getAll')->willReturn($scopes);

        $token = $this->tokenService->createToken('http://www.example.com', $owner, $client, $tokenScope);

        static::assertInstanceOf(AuthorizationCode::class, $token);
        static::assertEquals(40, strlen($token->getToken()));

        if (empty($tokenScope)) {
            static::assertCount(1, $token->getScopes());
        } else {
            static::assertEquals($tokenScope, $token->getScopes());
        }
    }

    public function testCreateNewTokenUntilOneDoesNotExist()
    {
        $this->scopeService->expects(static::once())->method('getDefaultScopes')->will(static::returnValue(['read']));

        $this->tokenRepository->expects(static::at(0))
            ->method('tokenExists')
            ->with(static::isType('string'))
            ->willReturn(true);

        $this->tokenRepository->expects(static::at(1))
            ->method('tokenExists')
            ->with(static::isType('string'))
            ->willReturn(false);

        $this->tokenRepository->expects(static::once())
            ->method('save')
            ->will(static::returnArgument(0));

        $owner  = $this->createMock(TokenOwnerInterface::class);
        $client = $this->createMock(Client::class);

        $token = $this->tokenService->createToken('http://www.example.com', $owner, $client, []);
        static::assertEquals(40, strlen($token->getToken()));
    }
}
