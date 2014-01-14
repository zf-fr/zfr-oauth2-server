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

namespace ZfrOAuth2\Server\Entity;

/**
 * Client entity
 *
 * A client is typically an application (either a third-party or your own application) that integrates with the
 * provider (in this case, you are the provider)
 *
 * There are two types of clients: the public and confidential ones. Some grants absolutely require a client,
 * while other don't need it. The reason is that for public clients (like a JavaScript application), the secret
 * cannot be kept... well... secret! To create a public client, you just need to let an empty secret. More
 * info about that: http://tools.ietf.org/html/rfc6749#section-2.1
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class Client
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string
     */
    protected $name;

    /**
     * @var string
     */
    protected $redirectUri;

    /**
     * Get the client id
     *
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set the client secret
     *
     * @param  string $secret
     * @return void
     */
    public function setSecret($secret)
    {
        $this->secret = (string) $secret;
    }

    /**
     * Get the client secret
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Set the client name
     *
     * @param  string $name
     * @return void
     */
    public function setName($name)
    {
        $this->name = (string) $name;
    }

    /**
     * Get the client name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Set the redirect URI
     *
     * @param  string $redirectUri
     * @return void
     */
    public function setRedirectUri($redirectUri)
    {
        $this->redirectUri = (string) $redirectUri;
    }

    /**
     * Get the redirect URI
     *
     * @return string
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * Is this client a public client?
     *
     * @return bool
     */
    public function isPublic()
    {
        return empty($this->secret);
    }
}
