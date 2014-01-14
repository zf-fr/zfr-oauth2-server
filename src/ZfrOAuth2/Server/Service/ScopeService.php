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
use ZfrOAuth2\Server\Entity\Scope;

/**
 * Scope service
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class ScopeService
{
    /**
     * @var ObjectManager
     */
    protected $objectManager;

    /**
     * @var ObjectRepository
     */
    protected $scopeRepository;

    /**
     * @param ObjectManager    $objectManager
     * @param ObjectRepository $scopeRepository
     */
    public function __construct(ObjectManager $objectManager, ObjectRepository $scopeRepository)
    {
        $this->objectManager   = $objectManager;
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * Create a new scope
     *
     * @param  Scope $scope
     * @return Scope
     */
    public function createScope(Scope $scope)
    {
        $this->objectManager->persist($scope);
        $this->objectManager->flush();

        return $scope;
    }

    /**
     * Get all the scopes
     *
     * @return Scope[]
     */
    public function getAll()
    {
        return $this->scopeRepository->findAll();
    }

    /**
     * Get all the default scopes
     *
     * @return Scope[]
     */
    public function getDefaultScopes()
    {
        return $this->scopeRepository->findBy(['isDefault' => true]);
    }
}
