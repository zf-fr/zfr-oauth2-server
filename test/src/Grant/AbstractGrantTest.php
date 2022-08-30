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

namespace ZfrOAuth2Test\Server\Grant;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use ZfrOAuth2\Server\Grant\AbstractGrant;
use ZfrOAuth2\Server\Model\AccessToken;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;

/**
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Grant\AbstractGrant
 */
class AbstractGrantTest extends TestCase
{
    public function testMethodGetType(): void
    {
        $abstractGrant = $this->getMockForAbstractClass(AbstractGrant::class);
        $this->assertSame('', $abstractGrant->getType());
    }

    public function testMethodGetResponseType(): void
    {
        $abstractGrant = $this->getMockForAbstractClass(AbstractGrant::class);
        $this->assertSame('', $abstractGrant->getResponseType());
    }

    /**
     * @dataProvider dpMethodPrepareTokenResponse
     */
    public function testMethodPrepareTokenResponse(
        ?RefreshToken $refreshToken,
        bool $useRefreshTokenScopes,
        ?TokenOwnerInterface $getOwner
    ): void {
        $abstractGrant = $this->getMockForAbstractClass(AbstractGrant::class);
        $accessToken   = $this->createMock(AccessToken::class);

        $accessToken->expects($this->once())->method('getOwner')->willReturn($getOwner);
        $accessToken->expects($this->once())->method('getExpiresIn');

        if ($getOwner) {
            $getOwner->expects($this->once())->method('getTokenOwnerId');
        }

        if ($useRefreshTokenScopes) {
            $refreshToken->expects($this->once())->method('getScopes');
        } else {
            $accessToken->expects($this->once())->method('getScopes');
        }

        if (null !== $refreshToken) {
            $refreshToken->expects($this->once())->method('getToken');
        }

        // calling protected method from abstract token scope
        $protectedBound = (function ($accessToken, $refreshToken, $useRefreshTokenScopes) {
            return $this->prepareTokenResponse($accessToken, $refreshToken, $useRefreshTokenScopes);
        })->bindTo($abstractGrant, $abstractGrant);

        $this->assertInstanceOf(
            ResponseInterface::class,
            $protectedBound($accessToken, $refreshToken, $useRefreshTokenScopes)
        );
    }

    public function dpMethodPrepareTokenResponse(): array
    {
        return [
            [
                $this->createMock(RefreshToken::class),
                true,
                $this->createMock(TokenOwnerInterface::class),
            ],
            [
                $this->createMock(RefreshToken::class),
                false,
                $this->createMock(TokenOwnerInterface::class),
            ],
            [
                null,
                false,
                $this->createMock(TokenOwnerInterface::class),
            ],
            [
                $this->createMock(RefreshToken::class),
                true,
                null,
            ],
            [
                $this->createMock(RefreshToken::class),
                false,
                null,
            ],
            [
                null,
                false,
                null,
            ],
        ];
    }
}
