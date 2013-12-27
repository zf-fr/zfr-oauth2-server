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

namespace ZfrOAuth2\Server\Exception;

use Exception;

/**
 * This class allow to create authorization exception.
 *
 * In this class, the normalized "error" code is set as the code parameter of the exception, while the
 * message is the "error_description"
 *
 * @link    http://tools.ietf.org/html/rfc6749#section-5.2
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class OAuth2Exception extends Exception implements ExceptionInterface
{
    /**
     * @param  string $description
     * @return OAuth2Exception
     */
    static public function invalidRequest($description)
    {
        return new self($description, 'invalid_request');
    }

    /**
     * @param  string $description
     * @return OAuth2Exception
     */
    static public function invalidClient($description)
    {
        return new self($description, 'invalid_client');
    }

    /**
     * @param  string $description
     * @return OAuth2Exception
     */
    static public function invalidGrant($description)
    {
        return new self($description, 'invalid_grant');
    }

    /**
     * @param  string $description
     * @return OAuth2Exception
     */
    static public function unauthorizedClient($description)
    {
        return new self($description, 'unauthorized_client');
    }

    /**
     * @param  string $description
     * @return OAuth2Exception
     */
    static public function unsupportedGrantType($description)
    {
        return new self($description, 'unsupported_grant_type');
    }

    /**
     * @param  string $description
     * @return OAuth2Exception
     */
    static public function invalidScope($description)
    {
        return new self($description, 'invalid_scope');
    }
}
