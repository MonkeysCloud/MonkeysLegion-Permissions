<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Cache;

use Psr\SimpleCache\CacheInterface;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Caches permission resolution results.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class CacheLayer
{
    /** @var array<string, mixed> */
    private array $memoized = [];

    public function __construct(
        private readonly ?CacheInterface $cache = null,
        private readonly string $prefix = 'perm:',
        private readonly int $ttl = 3600,
    ) {}

    public function get(string $key, callable $resolver): mixed
    {
        if (array_key_exists($key, $this->memoized)) {
            return $this->memoized[$key];
        }

        $fullKey = $this->prefix . $key;

        if ($this->cache !== null && $this->cache->has($fullKey)) {
            $value = $this->cache->get($fullKey);
            $this->memoized[$key] = $value;
            return $value;
        }

        $value = $resolver();

        $this->memoized[$key] = $value;

        if ($this->cache !== null) {
            $this->cache->set($fullKey, $value, $this->ttl);
        }

        return $value;
    }

    public function invalidate(string $key): void
    {
        unset($this->memoized[$key]);
        if ($this->cache !== null) {
            $this->cache->delete($this->prefix . $key);
        }
    }

    public function flush(): void
    {
        $this->memoized = [];
        if ($this->cache !== null) {
            // Note: In a real app we might only clear by prefix, but PSR-16 clear() wipes all.
            // Usually we'd bump a version key instead of clearing.
            $this->cache->clear();
        }
    }
}
