<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Core\Config\Configurable;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Works out the IP address of the visitor, also when the site is behind CloudFlare.
 *
 * Behind CloudFlare, the address that connects to our server (REMOTE_ADDR) is a CloudFlare server,
 * and the real visitor is in the CF-Connecting-IP header.
 * Anyone can send that header, so we ONLY believe it when the connection really comes from CloudFlare
 * (the published CloudFlare address ranges). For every other connection the header is ignored.
 *
 * To add another proxy (e.g. a load balancer that sits in front of this server, and behind CloudFlare),
 * add its address range to additional_trusted_proxy_ranges.
 *
 * The CloudFlare ranges are published on https://www.cloudflare.com/ips/ and do not change often.
 */
class ClientIp
{
    use Configurable;

    /**
     * @var string[]
     */
    private static array $cloudflare_ranges = [
        // https://www.cloudflare.com/ips-v4
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
        // https://www.cloudflare.com/ips-v6
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    /**
     * Other proxies that we trust to send us the real address of the visitor in CF-Connecting-IP.
     *
     * @var string[]
     */
    private static array $additional_trusted_proxy_ranges = [];

    /**
     * The IP address of the visitor, or 'unknown'.
     *
     * @param null|array $server defaults to $_SERVER
     */
    public static function get(?array $server = null): string
    {
        $server ??= $_SERVER;
        $peer = self::validIp($server['REMOTE_ADDR'] ?? null);
        if (null === $peer) {
            return 'unknown';
        }

        if (IpUtils::checkIp($peer, self::trustedRanges())) {
            $visitor = self::validIp($server['HTTP_CF_CONNECTING_IP'] ?? null);
            if (null !== $visitor) {
                return $visitor;
            }
        }

        return $peer;
    }

    /**
     * The value to count requests under: IPv4 addresses as they are,
     * IPv6 addresses as their /64 (one visitor usually gets a whole /64, so changing the
     * last part of the address must not give a new allowance).
     */
    public static function bucket(string $ip): string
    {
        $packed = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? @inet_pton($ip) : false;
        if (false === $packed) {
            return $ip;
        }

        return (string) inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . '/64';
    }

    /**
     * @return string[]
     */
    protected static function trustedRanges(): array
    {
        return array_values(array_filter(array_merge(
            (array) static::config()->get('cloudflare_ranges'),
            (array) static::config()->get('additional_trusted_proxy_ranges')
        ), 'is_string'));
    }

    /**
     * @param mixed $value
     */
    protected static function validIp($value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);
        if (! filter_var($value, FILTER_VALIDATE_IP)) {
            return null;
        }

        // IPv4 address written as IPv6 (::ffff:1.2.3.4)
        if (str_starts_with(strtolower($value), '::ffff:') && filter_var(substr($value, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return substr($value, 7);
        }

        return $value;
    }
}
