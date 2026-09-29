<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit\Policy;

use MonkeysLegion\Permissions\Policy\Policy;
use MonkeysLegion\Permissions\Policy\PolicyResolver;
use MonkeysLegion\Permissions\Tests\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;

final class PolicyResolverTest extends TestCase
{
    /** @var ContainerInterface&MockObject */
    private ContainerInterface $container;

    protected function setUp(): void
    {
        $this->container = $this->createMock(ContainerInterface::class);
    }

    public function test_resolve_returns_null_for_unmapped_class(): void
    {
        $resolver = new PolicyResolver($this->container, []);

        $result = $resolver->resolve('App\Entity\UnknownEntity');

        self::assertNull($result);
    }

    public function test_resolve_returns_null_for_null_resource(): void
    {
        $resolver = new PolicyResolver($this->container, []);

        $result = $resolver->resolve(null);

        self::assertNull($result);
    }

    public function test_resolve_returns_policy_for_mapped_class_string(): void
    {
        $policy = $this->createMock(Policy::class);

        $this->container
            ->method('get')
            ->with('App\Policy\PostPolicy')
            ->willReturn($policy);

        $resolver = new PolicyResolver($this->container, [
            'App\Entity\Post' => 'App\Policy\PostPolicy',
        ]);

        $result = $resolver->resolve('App\Entity\Post');

        self::assertSame($policy, $result);
    }

    public function test_resolve_returns_policy_for_object_resource(): void
    {
        $policy = $this->createMock(Policy::class);
        $resource = new \stdClass();

        $this->container
            ->method('get')
            ->with('App\Policy\StdClassPolicy')
            ->willReturn($policy);

        $resolver = new PolicyResolver($this->container, [
            'stdClass' => 'App\Policy\StdClassPolicy',
        ]);

        $result = $resolver->resolve($resource);

        self::assertSame($policy, $result);
    }

    public function test_resolve_detects_class_from_object_instance(): void
    {
        $resource = new \stdClass();
        $detectedClass = get_class($resource);

        $policy = $this->createMock(Policy::class);

        $this->container
            ->method('get')
            ->willReturn($policy);

        $resolver = new PolicyResolver($this->container, [
            $detectedClass => 'SomePolicy',
        ]);

        $result = $resolver->resolve($resource);

        self::assertSame($policy, $result);
    }
}

/**
 * Test stub Policy for testing the abstract base class behavior.
 */
final class TestPolicy extends Policy
{
    public function before(\MonkeysLegion\Auth\Contract\AuthenticatableInterface $identity, string $ability, mixed $resource = null): ?\MonkeysLegion\Permissions\Decision
    {
        return null;
    }
}
