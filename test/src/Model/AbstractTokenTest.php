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

use PHPUnit\Framework\TestCase;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;
use ZfrOAuth2Test\Server\Asset\SomeToken;

/**
 * @author  Bas Kamer <baskamer@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Model\AbstractToken
 */
class AbstractTokenTest extends TestCase
{
    public function setUp(): void
    {
        $this->owner = $this->createMock(TokenOwnerInterface::class);
        $this->client = $this->createMock(Client::class);
        $this->expiresAt = (new \DateTime())->modify('+60 seconds');
        $this->scopes = ['somescope', 'otherscope'];

        $this->token = SomeToken::reconstitute([
            'token' => 'a token',
            'expiresAt' => $this->expiresAt,
            'owner' => $this->owner,
            'client' => $this->client,
            'scopes' => $this->scopes,
        ]);
    }

    public function testMethodGetToken(): void
    {
        $this->assertSame('a token', $this->token->getToken());
    }

    public function testMethodGetOwner(): void
    {
        $this->assertSame($this->owner, $this->token->getOwner());
    }

    public function testMethodGetClient(): void
    {
        $this->assertSame($this->client, $this->token->getClient());
    }

    public function testMethodGetExpiresAt(): void
    {
        $this->assertSame($this->expiresAt->format(\DateTime::ATOM), $this->token->getExpiresAt()->format(\DateTime::ATOM));
    }

    public function testMethodGetExpiresIn(): void
    {
        $this->assertIsInt($this->token->getExpiresIn());
        $this->assertSame(60, $this->token->getExpiresIn());
    }

    public function testMethodGetIsExpired(): void
    {
        $this->assertIsBool($this->token->isExpired());
        $this->assertFalse($this->token->isExpired());
    }

    public function testMethodGetScopes(): void
    {
        $this->assertSame($this->scopes, $this->token->getScopes());
    }

    public function testMethodMatchScopes(): void
    {
        $this->assertTrue($this->token->matchScopes($this->scopes));
        $this->assertTrue($this->token->matchScopes('somescope'));

        $this->assertFalse($this->token->matchScopes('unknownscope'));
    }

    public function testMethodIsValid(): void
    {
        $this->assertTrue($this->token->isValid($this->scopes));
        $this->assertFalse($this->token->isValid('unknownscope'));
    }

    public function testMethodIsValidWithExpired(): void
    {
        // expired
        $this->expiresAt = (new \DateTime())->modify('-60 seconds');

        $this->token = SomeToken::reconstitute([
            'token' => 'a token',
            'expiresAt' => $this->expiresAt,
            'owner' => $this->owner,
            'client' => $this->client,
            'scopes' => $this->scopes,
        ]);

        $this->assertFalse($this->token->isValid('somescope'));
    }
}
