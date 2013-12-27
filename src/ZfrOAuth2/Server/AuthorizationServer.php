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

namespace ZfrOAuth2\Server;

use Zend\Http\Request as HttpRequest;

/**
 * The authorization server makes the glue between all the parts
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class AuthorizationServer
{
    /**
     * Validate the client
     *
     * @param HttpRequest $request
     * @param bool        $optionalSecret
     */
    public function validateClient(HttpRequest $request, $optionalSecret = false)
    {
        // We first try to get the Authorization header, as this is the recommended way according to the spec
        if ($header = $request->getHeader('Authorization')) {
            // The value is "Basic xxx", we are interested in the last part
            $parts = explode(' ', $header->getFieldValue());
            $value = base64_decode(end($parts));

            list($id, $secret) = explode(':', $value);
        } else {
            $id     = $request->getPost('client_id');
            $secret = $request->getPost('client_secret');
        }

        if (!$optionalSecret && !$secret) {
            throw OAuth2Exception::invalidClient('Client secret is missing');
        }

        $client = $this->clientService->getClient($id, $secret);

        if (null === $client) {
            throw OAuth2Exception::invalidClient('Client cannot be found');
        }

        // @TODO: validate grant type
    }
}
