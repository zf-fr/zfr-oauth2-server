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

namespace ZfrOAuth2\Server\Model;

/**
 * A scope is associated to a token and define the permissions of the token
 *
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 */
class Scope
{
    /**
     * @var int
     */
    private $id;

    /**
     * @var string
     */
    private $name = '';

    /**
     * @var string
     */
    private $description = '';

    /**
     * @var bool
     */
    private $isDefault = false;

    /**
     * Scope constructor.
     */
    private function __construct()
    {
    }

    /**
     * Create a new Scope
     *
     * @param int         $id
     * @param string      $name
     * @param string|null $description
     * @param bool        $isDefault
     * @return Scope
     */
    public static function createNewScope(
        int $id,
        string $name,
        string $description = null,
        bool $isDefault = false
    ): Scope {
        $scope = new static();

        $scope->id          = $id;
        $scope->name        = $name;
        $scope->description = $description;
        $scope->isDefault   = $isDefault;

        return $scope;
    }

    /**
     * @param array $data
     * @return Scope
     */
    public static function reconstitute(array $data): Scope
    {
        $scope = new static();

        $scope->id          = $data['id'];
        $scope->name        = $data['name'];
        $scope->description = $data['description'];
        $scope->isDefault   = $data['isDefault'];

        return $scope;
    }

    /**
     * Get the scope id
     *
     * @return int|null
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Get the scope's name
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Get the scope's description
     *
     * @return string
     */
    public function getDescription(): string
    {
        return $this->description;
    }

    /**
     * Is the scope a default scope?
     *
     * @return bool
     */
    public function isDefault(): bool
    {
        return $this->isDefault;
    }
}
