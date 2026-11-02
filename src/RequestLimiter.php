<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use Psr\SimpleCache\CacheInterface;

/**
 * Allows a number of requests per time period for a "bucket" (e.g. an IP address).
 * A sliding window: only the requests of the last $seconds count.
 *
 * Requests that are refused are not counted, so someone who keeps trying
 * is not kept out for longer than the time period.
 */
class RequestLimiter
{
    public function __construct(
        protected CacheInterface $cache,
        protected int $maxRequests,
        protected int $seconds,
        protected string $name = 'send'
    ) {
    }

    /**
     * Counts a request for the bucket, unless it has had too many.
     *
     * @return bool TRUE if this request is allowed
     */
    public function allow(string $bucket, ?int $now = null): bool
    {
        if ($this->maxRequests <= 0 || $this->seconds <= 0) {
            return true;
        }

        $now ??= time();
        $key = 'OneTimeCodeLimit_' . md5($this->name . '|' . $bucket);
        $recent = array_filter(
            (array) $this->cache->get($key, []),
            fn ($time) => is_int($time) && $time > $now - $this->seconds
        );
        if (count($recent) >= $this->maxRequests) {
            return false;
        }

        $recent[] = $now;
        $this->cache->set($key, array_values($recent), $this->seconds);

        return true;
    }
}
