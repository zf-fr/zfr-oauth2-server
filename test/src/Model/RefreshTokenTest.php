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

namespace ZfrOAuth2Test\Server\Model;

use DateTime;
use DateTimeImmutable;
use DateTimeInterface;
use PHPUnit\Framework\TestCase;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\RefreshToken;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;

use function count;
use function is_array;
use function strlen;

/**
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Model\AbstractToken
 * @covers  \ZfrOAuth2\Server\Model\RefreshToken
 */
class RefreshTokenTest extends TestCase
{
    /**
     * @dataProvider providerGenerateNewRefreshToken
     */
    public function testGenerateNewAccessToken(
        int $ttl,
        ?TokenOwnerInterface $owner,
        ?Client $client,
        ?array $scopes
    ): void {
        /** @var RefreshToken $refreshToken */
        $refreshToken = RefreshToken::createNewRefreshToken($ttl, $owner, $client, $scopes);

        $this->assertNotEmpty($refreshToken->getToken());
        $this->assertEquals(40, strlen($refreshToken->getToken()));
        if (is_array($scopes)) {
            $this->assertCount(count($scopes), $refreshToken->getScopes());
        }
        $this->assertSame($client, $refreshToken->getClient());
        $this->assertSame($owner, $refreshToken->getOwner());

        // with a ttl = 0, getExpiresAt must return null
        if ($ttl === 0) {
            $this->assertNull($refreshToken->getExpiresAt());
        } else {
            $this->assertInstanceOf(DateTimeInterface::class, $refreshToken->getExpiresAt());
            $this->assertEquals(
                (new DateTimeImmutable())->modify("+$ttl seconds")->format(DateTime::ATOM),
                $refreshToken->getExpiresAt()->format(DateTime::ATOM)
            );
        }
    }

    public function providerGenerateNewRefreshToken(): array
    {
        return [
            [
                3600,
                $this->createMock(TokenOwnerInterface::class),
                $this->createMock(Client::class),
                ['scope1', 'scope2'],
            ],
            [
                3600,
                $this->createMock(TokenOwnerInterface::class),
                $this->createMock(Client::class),
                ['scope1'],
            ],
            [3600, null, null, null],
            [0, null, null, null],
        ];
    }

    /**
     * @dataProvider providerReconstitute
     */
    public function testReconstitute(array $data): void
    {
        /** @var RefreshToken $refreshToken */
        $refreshToken = RefreshToken::reconstitute($data);

        $this->assertEquals($data['token'], $refreshToken->getToken());
        $this->assertSame($data['owner'], $refreshToken->getOwner());
        $this->assertSame($data['client'], $refreshToken->getClient());

        if ($data['expiresAt'] instanceof DateTimeImmutable) {
            /** @var DateTimeImmutable $expiresAt */
            $expiresAt = $data['expiresAt'];
            $this->assertSame($expiresAt->getTimeStamp(), $refreshToken->getExpiresAt()->getTimestamp());
        } else {
            $this->assertNull($refreshToken->getExpiresAt());
        }

        $this->assertSame($data['scopes'], $refreshToken->getScopes());
    }

    public function providerReconstitute(): array
    {
        return [
            [
                [
                    'token'     => 'token',
                    'owner'     => $this->createMock(TokenOwnerInterface::class),
                    'client'    => $this->createMock(Client::class),
                    'expiresAt' => new DateTimeImmutable(),
                    'scopes'    => ['scope1', 'scope2'],
                ],
            ],
            [ // test set - null values
                [
                    'token'     => 'token',
                    'owner'     => null,
                    'client'    => null,
                    'expiresAt' => null,
                    'scopes'    => [],
                ],
            ],
        ];
    }

    public function testCalculateExpiresIn(): void
    {
        $refreshToken = RefreshToken::createNewRefreshToken(60);

        $this->assertFalse($refreshToken->isExpired());
        $this->assertEquals(60, $refreshToken->getExpiresIn());
    }

    public function testCanCheckIfATokenIsExpired(): void
    {
        $refreshToken = RefreshToken::createNewRefreshToken(-60);

        $this->assertTrue($refreshToken->isExpired());
    }

    public function testSupportLongLiveToken(): void
    {
        $refreshToken = RefreshToken::createNewRefreshToken(60);
        $this->assertFalse($refreshToken->isExpired());
    }

    public function testIsValid(): void
    {
        $accessToken = RefreshToken::createNewRefreshToken(60, null, null, ['read', 'write']);
        $this->assertTrue($accessToken->isValid('read'));

        $accessToken = RefreshToken::createNewRefreshToken(-60, null, null, ['read', 'write']);
        $this->assertFalse($accessToken->isValid('read'));

        $accessToken = RefreshToken::createNewRefreshToken(60, null, null, ['read', 'write']);
        $this->assertFalse($accessToken->isValid('delete'));
    }
}
