<?php

declare(strict_types = 1);

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

namespace ZfrOAuth2\Server\Exception;

use Exception;

/**
 * This class allow to create authorization exception.
 *
 * In this class, the normalized "error" code is set as the code parameter of the exception, while the
 * message is the "error_description".
 *
 * @link    http://tools.ietf.org/html/rfc6749#section-5.2
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class OAuth2Exception extends Exception implements ExceptionInterface
{
    /**
     * Override the constructor to allow $code as a string
     */
    public function __construct(string $message, string $code)
    {
        parent::__construct($message);
        $this->code = (string) $code;
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function accessDenied(string $description): OAuth2Exception
    {
        return new self($description, 'access_denied');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function invalidRequest(string $description): OAuth2Exception
    {
        return new self($description, 'invalid_request');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function invalidClient(string $description): OAuth2Exception
    {
        return new self($description, 'invalid_client');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function invalidGrant(string $description): OAuth2Exception
    {
        return new self($description, 'invalid_grant');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function invalidScope(string $description): OAuth2Exception
    {
        return new self($description, 'invalid_scope');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function serverError(string $description): OAuth2Exception
    {
        return new self($description, 'server_error');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function temporarilyUnavailable(string $description): OAuth2Exception
    {
        return new self($description, 'temporarily_unavailable');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function unauthorizedClient(string $description): OAuth2Exception
    {
        return new self($description, 'unauthorized_client');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function unsupportedGrantType(string $description): OAuth2Exception
    {
        return new self($description, 'unsupported_grant_type');
    }

    /**
     * @todo Explain when this excpetion is applicable
     */
    public static function unsupportedResponseType(string $description): OAuth2Exception
    {
        return new self($description, 'unsupported_response_type');
    }

    /**
     * @link   https://tools.ietf.org/html/rfc7009#section-2.2.1
     * @return OAuth2Exception
     */
    public static function unsupportedTokenType(string $description): OAuth2Exception
    {
        return new self($description, 'unsupported_token_type');
    }
}
