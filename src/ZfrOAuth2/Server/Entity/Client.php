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
 * A client is an application that makes protected resources on behalf of the resource owner (eg. a user
 * for instance). A client can be, for instance, a server or a browser
 *
 * There are two types of clients: the public and confidential ones. Some grants absolutely require a client,
 * while other don't need it. The reason is that for public clients (like a JavaScript application), the secret
 * cannot be kept, well, secret! To create a public client, you just need to let an empty secret
 *
 * Note that the client implements TokenOwnerInterface, because in the "ClientCredentials" grant type, the
 * owner of the tokens is actually the client itself
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class Client implements TokenOwnerInterface
{
    /**
     * @var int
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
     * @var string
     */
    protected $grantTypes;

    /**
     * Get the client id
     *
     * @return int
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
     * Set the grant types (it must be a string of space separated grant types)
     *
     * @param string $grantTypes
     */
    public function setGrantTypes($grantTypes)
    {
        $this->grantTypes = (string) $grantTypes;
    }

    /**
     * Get the grant types
     *
     * @return string
     */
    public function getGrantTypes()
    {
        return $this->grantTypes;
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

    /**
     * {@inheritDoc}
     */
    public function getTokenOwnerId()
    {
        return $this->id;
    }
}
