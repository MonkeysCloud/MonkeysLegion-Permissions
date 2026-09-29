<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Tests\Unit\Cache;

use MonkeysLegion\Permissions\Cache\CacheLayer;
use MonkeysLegion\Permissions\Tests\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\SimpleCache\CacheInterface;

final class CacheLayerTest extends TestCase
{
    public function test_get_calls_resolver_on_first_call(): void
    {
        $layer = new CacheLayer();
        $callCount = 0;

        $result = $layer->get('key1', function () use (&$callCount) {
            $callCount++;
            return 'value1';
        });

        self::assertSame('value1', $result);
        self::assertSame(1, $callCount);
    }

    public function test_get_returns_memoized_value_on_second_call(): void
    {
        $layer = new CacheLayer();
        $callCount = 0;

        $resolver = function () use (&$callCount) {
            $callCount++;
            return 'value';
        };

        $layer->get('key', $resolver);
        $layer->get('key', $resolver);

        self::assertSame(1, $callCount);
    }

    public function test_get_uses_psr16_cache_when_available(): void
    {
        /** @var CacheInterface&MockObject $cache */
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('has')->willReturn(true);
        $cache->method('get')->willReturn('cached-value');

        $layer = new CacheLayer(cache: $cache);
        $callCount = 0;

        $result = $layer->get('key', function () use (&$callCount) {
            $callCount++;
            return 'fresh-value';
        });

        self::assertSame('cached-value', $result);
        self::assertSame(0, $callCount);
    }

    public function test_get_writes_to_psr16_cache_on_miss(): void
    {
        /** @var CacheInterface&MockObject $cache */
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('has')->willReturn(false);
        $cache->expects(self::once())
            ->method('set')
            ->with('perm:key', 'value', 3600);

        $layer = new CacheLayer(cache: $cache);

        $layer->get('key', fn() => 'value');
    }

    public function test_get_uses_custom_prefix(): void
    {
        /** @var CacheInterface&MockObject $cache */
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('has')->willReturn(false);
        $cache->expects(self::once())
            ->method('set')
            ->with('custom:key', 'value', 3600);

        $layer = new CacheLayer(cache: $cache, prefix: 'custom:');

        $layer->get('key', fn() => 'value');
    }

    public function test_get_uses_custom_ttl(): void
    {
        /** @var CacheInterface&MockObject $cache */
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('has')->willReturn(false);
        $cache->expects(self::once())
            ->method('set')
            ->with('perm:key', 'value', 7200);

        $layer = new CacheLayer(cache: $cache, ttl: 7200);

        $layer->get('key', fn() => 'value');
    }

    public function test_invalidate_removes_memoized_value(): void
    {
        $layer = new CacheLayer();
        $callCount = 0;

        $resolver = function () use (&$callCount) {
            $callCount++;
            return "value{$callCount}";
        };

        $first  = $layer->get('key', $resolver);
        $layer->invalidate('key');
        $second = $layer->get('key', $resolver);

        self::assertSame('value1', $first);
        self::assertSame('value2', $second);
        self::assertSame(2, $callCount);
    }

    public function test_invalidate_removes_from_psr16_cache(): void
    {
        /** @var CacheInterface&MockObject $cache */
        $cache = $this->createMock(CacheInterface::class);
        $cache->expects(self::once())->method('delete')->with('perm:key');

        $layer = new CacheLayer(cache: $cache);

        $layer->invalidate('key');
    }

    public function test_flush_clears_all_memoized_values(): void
    {
        $layer = new CacheLayer();
        $callCount = 0;

        $resolver = function () use (&$callCount) {
            $callCount++;
            return "value{$callCount}";
        };

        $layer->get('key1', $resolver);
        $layer->get('key2', $resolver);
        $layer->flush();

        $layer->get('key1', $resolver);

        self::assertSame(3, $callCount); // key1 resolved twice, key2 once.
    }

    public function test_flush_clears_psr16_cache(): void
    {
        /** @var CacheInterface&MockObject $cache */
        $cache = $this->createMock(CacheInterface::class);
        $cache->expects(self::once())->method('clear');

        $layer = new CacheLayer(cache: $cache);

        $layer->flush();
    }

    public function test_get_without_psr16_cache_works(): void
    {
        $layer = new CacheLayer();

        $result = $layer->get('key', fn() => 42);

        self::assertSame(42, $result);
    }
}
