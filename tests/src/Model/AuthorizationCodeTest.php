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

use ZfrOAuth2\Server\Model\AuthorizationCode;
use ZfrOAuth2\Server\Model\Client;
use ZfrOAuth2\Server\Model\TokenOwnerInterface;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Model\AbstractToken
 * @covers  \ZfrOAuth2\Server\Model\AuthorizationCode
 */
class AuthorizationCodeTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider providerGenerateNewAuthorizationCode
     */
    public function testGenerateNewAuthorizationCode($redirectUri)
    {
        /** @var AuthorizationCode $authorizationCode */
        $authorizationCode = AuthorizationCode::createNewAuthorizationCode(3600, $redirectUri);

        if (null !== $redirectUri) {
            $this->assertSame($redirectUri, $authorizationCode->getRedirectUri());
        } else {
            $this->assertEmpty($authorizationCode->getRedirectUri());
        }
    }

    public function providerGenerateNewAuthorizationCode()
    {
        return [
            [''],
            ['http://www.example.com'],
            [null]
        ];
    }

    /**
     * @dataProvider providerReconstitute
     */
    public function testReconstitute($data)
    {
        /** @var AuthorizationCode $authorizationCode */
        $authorizationCode = AuthorizationCode::reconstitute($data);

        $this->assertSame($data['redirectUri'], $authorizationCode->getRedirectUri());
    }

    public function providerReconstitute()
    {
        return [
            [
                [
                    'token'     => 'token',
                    'owner'     => null,
                    'client'    => null,
                    'expiresAt' => null,
                    'scopes'    => [],
                    'redirectUri' => 'http://www.example.com',
                ]
            ],
            [
                [
                    'token'     => 'token',
                    'owner'     => null,
                    'client'    => null,
                    'expiresAt' => null,
                    'scopes'    => [],
                    'redirectUri' => '',
                ]
            ],
        ];
    }

    public function testCalculateExpiresIn()
    {
        $authorizationCode = AuthorizationCode::createNewAuthorizationCode(60);

        $this->assertFalse($authorizationCode->isExpired());
        $this->assertEquals(60, $authorizationCode->getExpiresIn());
    }

    public function testCanCheckIfATokenIsExpired()
    {
        $authorizationCode = AuthorizationCode::createNewAuthorizationCode(-60);

        $this->assertTrue($authorizationCode->isExpired());
    }

    public function testSupportLongLiveToken()
    {
        $authorizationCode = AuthorizationCode::createNewAuthorizationCode(60);
        $this->assertFalse($authorizationCode->isExpired());
    }

    public function testIsValid()
    {
        $authorizationCode = AuthorizationCode::createNewAuthorizationCode(60, 'http://www.example.com', null, null, 'read write');
        $this->assertTrue($authorizationCode->isValid('read'));

        $authorizationCode = AuthorizationCode::createNewAuthorizationCode(-60, 'http://www.example.com', null, null, 'read write');
        $this->assertFalse($authorizationCode->isValid('read'));

        $authorizationCode = AuthorizationCode::createNewAuthorizationCode(60, 'http://www.example.com', null, null, 'read write');
        $this->assertFalse($authorizationCode->isValid('delete'));
    }

    /**
     * @todo I don't get this check
     */
    public function testDoNotSupportLongLiveToken()
    {
        $authorizationCode = AuthorizationCode::createNewAuthorizationCode(0, 'http://www.example.com', null, null, 'read write');
        $this->assertTrue($authorizationCode->isExpired());
    }
}
