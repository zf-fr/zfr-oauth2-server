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

namespace ZfrOAuth2Test\Server\Service;

use PHPUnit\Framework\TestCase;
use ZfrOAuth2\Server\Model\Scope;
use ZfrOAuth2\Server\Repository\ScopeRepositoryInterface;
use ZfrOAuth2\Server\Service\ScopeService;

/**
 * @author  Bas Kamer <baskamer@gmail.com>
 * @licence MIT
 * @covers  \ZfrOAuth2\Server\Service\ScopeService
 */
class ScopeServiceTest extends TestCase
{
    /**
     * @var ScopeRepositoryInterface
     */
    protected $scopeRepository;

    public function setUp()
    {
        $this->scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $this->tokenService    = new ScopeService($this->scopeRepository);
    }

    public function testCanCreateScope()
    {
        $scope = Scope::createNewScope(1, 'name');
        $this->scopeRepository->expects($this->once())
            ->method('save')
            ->with($scope)
            ->willReturn($scope);

        $this->tokenService->createScope($scope);
    }

    public function testCanGetAllScopesFromRepository()
    {
        $this->scopeRepository->expects($this->once())
            ->method('findAllScopes')
            ->with();

        $this->tokenService->getAll();
    }


    public function testGetDefaultScopes()
    {
        $this->scopeRepository->expects($this->once())
            ->method('findDefaultScopes')
            ->with()
            ->willReturn([]);

        $this->assertInternalType('array', $this->tokenService->getDefaultScopes());
    }
}
