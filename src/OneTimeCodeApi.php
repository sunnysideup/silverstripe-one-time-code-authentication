<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\Email\Email;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Extensible;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Security\Member;

class OneTimeCodeApi
{
    use Extensible;
    use Injectable;
    use Configurable;

    private static $subject = 'Your One Time Code';

    private static bool $send_with_sms = false;

    /**
     * When the email address does not belong to a member, we wait a moment before we respond,
     * so that the response does not come back (much) faster than when an email is sent.
     * Keep this short: the PHP process is busy while it waits.
     */
    private static int $unknown_email_delay_milliseconds = 300;

    /**
     * returns 0 on failure
     * returns 1 on success
     * @param array $data - should contain 'Email' OR Phone
     */
    public function SendOneTimeCode(array $data, HTTPRequest $request): int
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
        } else {
            // fake (part of) the time it takes to send an email, to make it harder to find out
            // which email addresses have an account. This is a short, fixed wait on purpose:
            // long or random waits would let anyone tie up the web server with lots of requests.
            $delay = (int) $this->config()->get('unknown_email_delay_milliseconds');
            if ($delay > 0) {
                usleep($delay * 1000);
            }
        }

        // Always mark the session the same way so the code-entry form is shown
        // regardless of whether the email matched, preventing enumeration.
        $request->getSession()->set('OneTimeCodeSent', true);
        $request->getSession()->set('OneTimeCodeEmail', $email);
        return $outcome;
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
