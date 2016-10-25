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

namespace ZfrOAuth2Test\Server\Options;

use ZfrOAuth2\Server\Grant\ClientCredentialsGrant;
use ZfrOAuth2\Server\Options\ServerOptions;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 *
 * @covers  \ZfrOAuth2\Server\Options\ServerOptions
 */
class ServerOptionsTest extends \PHPUnit_Framework_TestCase
{
    public function testDefaults()
    {
        $options = ServerOptions::fromArray();

        static::assertEquals(120, $options->getAuthorizationCodeTtl());
        static::assertEquals(3600, $options->getAccessTokenTtl());
        static::assertEquals(86400, $options->getRefreshTokenTtl());
        static::assertNull($options->getOwnerCallable());
        static::assertEmpty($options->getGrants());
        static::assertFalse($options->getRotateRefreshTokens());
        static::assertTrue($options->getRevokeRotatedRefreshTokens());
    }

    public function testGetters()
    {
        $callable = function () {
        };

        $options = ServerOptions::fromArray([
            'authorization_code_ttl'        => 300,
            'access_token_ttl'              => 3000,
            'refresh_token_ttl'             => 30000,
            'rotate_refresh_tokens'         => true,
            'revoke_rotated_refresh_tokens' => false,
            'owner_callable'                => $callable,
            'grants'                        => [ClientCredentialsGrant::class]
        ]);

        static::assertEquals(300, $options->getAuthorizationCodeTtl());
        static::assertEquals(3000, $options->getAccessTokenTtl());
        static::assertEquals(30000, $options->getRefreshTokenTtl());
        static::assertEquals(true, $options->getRotateRefreshTokens());
        static::assertEquals(false, $options->getRevokeRotatedRefreshTokens());
        static::assertSame($callable, $options->getOwnerCallable());
        static::assertEquals([ClientCredentialsGrant::class], $options->getGrants());
    }
}
