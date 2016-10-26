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

namespace ZfrOAuth2Test\Server\Exception;

use ZfrOAuth2\Server\Exception\OAuth2Exception;

/**
 * @author  Bas Kamer <baskamer@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Exception\OAuth2Exception
 */
class OAuth2ExceptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param $errorName
     * @param $errorCode
     * @dataProvider dataproviderErrorsCode
     */
    public function testErrorsCode($errorName, $expectedErrorCode)
    {
        $exception = OAuth2Exception::$errorName('description');

        $this->assertInstanceOf(OAuth2Exception::class, $exception);
        $this->assertSame('description', $exception->getMessage());
        $this->assertSame($expectedErrorCode, $exception->getCode());
    }

    public function dataproviderErrorsCode()
    {
        return [
            ['accessDenied', 'access_denied'],
            ['invalidRequest', 'invalid_request'],
            ['invalidClient', 'invalid_client'],
            ['invalidGrant', 'invalid_grant'],
            ['invalidScope', 'invalid_scope'],
            ['serverError', 'server_error'],
            ['temporarilyUnavailable', 'temporarily_unavailable'],
            ['unauthorizedClient', 'unauthorized_client'],
            ['unsupportedGrantType', 'unsupported_grant_type'],
            ['unsupportedResponseType', 'unsupported_response_type'],
            ['unsupportedTokenType', 'unsupported_token_type'],
        ];
    }
}
