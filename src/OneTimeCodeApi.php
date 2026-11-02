<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\Email\Email;
use Psr\SimpleCache\CacheInterface;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Extensible;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;
use Throwable;

class OneTimeCodeApi
{
    use Extensible;
    use Injectable;
    use Configurable;

    private static $subject = 'Your One Time Code';

    private static bool $send_with_sms = false;

    /**
     * Every request to send a code takes (at least) this long, whatever the outcome
     * (email known, unknown, or sent too recently). Otherwise the time it takes to respond
     * would show whether an email address has an account (sending an email takes a while).
     * Choose a time that is longer than it normally takes to send an email.
     * NB: the PHP process is busy while it waits, which is why the number of requests
     * per IP address is limited (see below). Set to 0 to switch this off.
     */
    private static int $send_code_minimum_duration_milliseconds = 1000;

    /**
     * The number of code requests that one visitor (IP address) can make in the time period below.
     * Set to 0 for no limit.
     */
    private static int $send_code_max_requests_per_ip = 10;

    private static int $send_code_period_seconds = 600;

    /**
     * returns -1 when this visitor has made too many requests (nothing has been done)
     * returns 0 on failure
     * returns 1 on success
     * @param array $data - should contain 'Email' OR Phone
     */
    public function SendOneTimeCode(array $data, HTTPRequest $request): int
    {
        // 1. not too many requests from one visitor.
        // (these are not slowed down: the refusal does not depend on the email address, so it tells nothing about accounts)
        if (! $this->requestIsAllowedForThisVisitor()) {
            return -1;
        }

        // 2. every other request takes the same time.
        $start = $this->now();
        $outcome = $this->processSendRequest($data, $request);
        $this->waitUntilMinimumDuration($start);

        return $outcome;
    }

    protected function processSendRequest(array $data, HTTPRequest $request): int
    {
        // the email has to be a single value (not e.g. an array)
        if (! is_string($data['Email'] ?? null)) {
            return 0;
        }

        $email = Convert::raw2sql($data['Email']);
        if (! $email) {
            return 0;
        }
        $identifierField = Member::config()->get('unique_identifier_field') ?? 'Email';
        $member = Member::get()
            ->filter([$identifierField => $email])
            ->first();

        $outcome = 1;
        if ($member) {
            // NB: there is no "locked out" state: failed attempts are counted per code
            // (see OneTimeCodeLoginHandler) and a new code starts with a clean slate.
            // Otherwise anyone could lock any member out by entering wrong codes.
            if ($this->withinResendCooldown($member)) {
                // Rate-limited: silently skip re-sending to prevent email bombing
                // and rapid brute-force code cycling.
                $outcome = 1;
            } else {
                $member->generateOneTimeCode();
                $this->SendOneTimeCodeInner($member);
            }
        }

        // Always mark the session the same way so the code-entry form is shown
        // regardless of whether the email matched, preventing enumeration.
        $request->getSession()->set('OneTimeCodeSent', true);
        $request->getSession()->set('OneTimeCodeEmail', $email);
        return $outcome;
    }

    /**
     * Counts this request for the IP address of the visitor, and says if it is allowed.
     * The IP address is the real one, also when the site is behind CloudFlare (see ClientIp).
     */
    protected function requestIsAllowedForThisVisitor(): bool
    {
        $max = (int) $this->config()->get('send_code_max_requests_per_ip');
        $seconds = (int) $this->config()->get('send_code_period_seconds');
        if ($max <= 0 || $seconds <= 0) {
            return true;
        }

        try {
            $limiter = new RequestLimiter($this->getLimiterCache(), $max, $seconds);

            return $limiter->allow(ClientIp::bucket($this->getVisitorIp()));
        } catch (Throwable $throwable) {
            // if the cache does not work, we do not want nobody to be able to log in.
            Injector::inst()->get(LoggerInterface::class)->error('One time code: could not limit requests: ' . $throwable->getMessage());

            return true;
        }
    }

    protected function getVisitorIp(): string
    {
        return ClientIp::get();
    }

    protected function getLimiterCache(): CacheInterface
    {
        return Injector::inst()->get(CacheInterface::class . '.OneTimeCode');
    }

    protected function now(): float
    {
        return microtime(true);
    }

    /**
     * Waits for the rest of the minimum duration (if any is left).
     */
    protected function waitUntilMinimumDuration(float $start): void
    {
        $minimum = (int) $this->config()->get('send_code_minimum_duration_milliseconds');
        if ($minimum <= 0) {
            return;
        }

        $remaining = (int) round(($minimum / 1000 - ($this->now() - $start)) * 1000000);
        if ($remaining > 0) {
            $this->sleepFor($remaining);
        }
    }

    protected function sleepFor(int $microseconds): void
    {
        usleep($microseconds);
    }

    /**
     * True when a code was sent to this member more recently than the configured
     * cooldown window.
     */
    protected function withinResendCooldown(Member $member): bool
    {
        $cooldown = (int) $member->config()->get('one_time_code_resend_cooldown_seconds');
        if ($cooldown <= 0) {
            return false;
        }
        $lastSent = $member->OneTimeCodeLastSent;
        if (! $lastSent) {
            return false;
        }
        return (time() - strtotime((string) $lastSent)) < $cooldown;
    }

    public function SendOneTimeCodeInner(?Member $member = null): void
    {
        if ($member && $member->isInDB()) {
            $subject = $this->config()->get('subject');

            if ($this->config()->get('send_with_sms')) {
                // SMS integration is site-specific and must be implemented by the user.
                $this->extend('updateSendOneTimeCodeViaSMS', $member, $subject);
            } else {
                $email = Email::create()
                    ->setHTMLTemplate('Sunnysideup\\OneTimeCode\\Email\\OneTimeCodeLoginEmail')
                    ->setData($member)
                    ->setSubject($subject)
                    ->setTo($member->Email);
                $email->send();
            }
        }
    }
}
