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

namespace ZfrOAuth2\Server\Service;

use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use Zend\Crypt\Password\Bcrypt;
use Zend\Math\Rand;
use ZfrOAuth2\Server\Entity\Client;
use ZfrOAuth2\Server\Exception\OAuth2Exception;

/**
 * Client service
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class ClientService
{
    /**
     * @var ObjectManager
     */
    protected $objectManager;

    /**
     * @var ObjectRepository
     */
    protected $clientRepository;

    /**
     * @var ObjectRepository
     */
    protected $scopeRepository;

    /**
     * @var Bcrypt
     */
    protected $bcrypt;

    /**
     * @var string
     */
    protected $defaultScope = '';

    /**
     * @param ObjectManager    $objectManager
     * @param ObjectRepository $clientRepository
     * @param ObjectRepository $scopeRepository
     */
    public function __construct(
        ObjectManager $objectManager,
        ObjectRepository $clientRepository,
        ObjectRepository $scopeRepository
    ) {
        $this->objectManager    = $objectManager;
        $this->clientRepository = $clientRepository;
        $this->scopeRepository  = $scopeRepository;
        $this->bcrypt           = new Bcrypt();
    }

    /**
     * Set the default scope that is used when registering a client, if none is set
     *
     * @param  string $defaultScope
     * @return void
     */
    public function setDefaultScope($defaultScope)
    {
        $this->defaultScope = (string) $defaultScope;
    }

    /**
     * Register a new client, and return the client secret before it was encryption
     *
     * Please note that the secret must be really kept secret, as it is used for some grant type to
     * authorize the client
     *
     * @param  Client $client
     * @return string
     */
    public function registerClient(Client $client)
    {
        // The client may have scopes. We must make sure that it does not have unknown scope values
        $scope = $client->getScope();

        if (!empty($scope)) {
            $this->validateClientScopes($scope);
        } else {
            $client->setScope($this->defaultScope);
        }

        // If no name was specified for the client, generate a unique one
        $name = $client->getName();
        if (empty($name)) {
            $client->setName(uniqid());
        }

        // Finally, we must generate a strong, unique secret, and crypt it before storing it
        $secret = Rand::getBytes(40, true);
        $client->setSecret($this->bcrypt->create($secret));

        $this->objectManager->persist($client);
        $this->objectManager->flush();

        return $secret;
    }

    /**
     * Get the client using its id
     *
     * @param  string      $id
     * @return Client|null
     */
    public function getClient($id)
    {
        return $this->clientRepository->findOneBy(['id' => $id]);
    }

    /**
     * Check if the client is valid by checking the secret
     *
     * If $allowPublicClients, this means that we do not need a secret to validate the client
     *
     * @param  Client $client
     * @param  string $secret
     * @param  bool   $allowPublicClients
     * @return bool
     */
    public function isClientValid(Client $client, $secret, $allowPublicClients)
    {
        if ($allowPublicClients) {
            return true;
        }

        return $this->bcrypt->verify($secret, $client->getSecret());
    }

    /**
     * Utility method that load all the scopes of the application, and check if the client does not
     * ask for scopes that do not exist
     *
     * @TODO: we are loading the whole scope table here. Not sure if this a good idea, but I suppose that
     *        scopes are limited
     *
     * @param  string $scope
     * @return void
     * @throws OAuth2Exception
     */
    protected function validateClientScopes($scope)
    {
        /* @var \ZfrOAuth2\Server\Entity\Scope[] $scopes */
        $scopes = $this->scopeRepository->findAll();

        foreach ($scopes as &$scope) {
            $scope = $scope->getName();
        }

        $clientScopes = explode(' ', (string) $scope);

        if (count(array_diff($clientScopes, $scopes)) > 0) {
            throw OAuth2Exception::invalidRequest('Client is asking for scopes that do not exist');
        }
    }
}
