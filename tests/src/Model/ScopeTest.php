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

namespace ZfrOAuth2Test\Server\Model;

use ZfrOAuth2\Server\Model\Scope;

/**
 * @author  Michaël Gallego <mic.gallego@gmail.com>
 * @licence MIT
 * @covers \ZfrOAuth2\Server\Model\Scope
 */
class ScopeTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider providerGenerateNewScope
     */
    public function testGenerateNewScope($id, $name, $description, $isDefault)
    {
        /** @var Scope $scope */
        $scope = Scope::createNewScope($id, $name, $description, $isDefault);

        $this->assertEquals($id, $scope->getId());
        $this->assertEquals($name, $scope->getName());
        $this->assertEquals($description, $scope->getDescription());
        $this->assertEquals($isDefault, $scope->isDefault());
    }

    public function providerGenerateNewScope()
    {
        return [
            [1, 'name', 'description', false],
            [1, 'name', 'description', true],
        ];
    }

    /**
     * @dataProvider providerReconstitute
     */
    public function testReconstitute($data)
    {
        $scope = Scope::reconstitute($data);

        $this->assertEquals($data['id'], $scope->getId());
        $this->assertSame($data['name'], $scope->getName());
        $this->assertSame($data['description'], $scope->getDescription());
        $this->assertEquals($data['isDefault'], $scope->isDefault());
    }

    public function providerReconstitute()
    {
        return [
            [
                ['id' => 1, 'name' => 'name', 'description' => 'description', 'isDefault' => true],
                ['id' => 1, 'name' => 'name', 'description' => null, 'isDefault' => false],
            ],
        ];
    }
}
