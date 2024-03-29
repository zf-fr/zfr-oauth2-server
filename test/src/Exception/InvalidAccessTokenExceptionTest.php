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

namespace ZfrOAuth2Test\Server\Exception;

use PHPUnit\Framework\TestCase;
use ZfrOAuth2\Server\Exception\InvalidAccessTokenException;

/**
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Exception\InvalidAccessTokenException
 */
class InvalidAccessTokenExceptionTest extends TestCase
{
    /**
     * @dataProvider dataproviderErrorsCode
     */
    public function testErrorsCode(string $errorName, string $expectedErrorCode): void
    {
        $exception = InvalidAccessTokenException::$errorName('description');

        $this->assertInstanceOf(InvalidAccessTokenException::class, $exception);
        $this->assertSame('description', $exception->getMessage());
        $this->assertSame($expectedErrorCode, $exception->getCode());
    }

    public function dataproviderErrorsCode(): array
    {
        return [
            ['invalidToken', 'invalid_token'],
        ];
    }
}
