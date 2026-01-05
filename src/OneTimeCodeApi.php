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
     *
     * return -1 when max attempts has been exceeded.
     * returns 0 on failure
     * returns 1 on success
     * @param array $data - should contain 'Email' OR Phone
     * @param HTTPRequest $request
     * @return int
     */
    public function SendOneTimeCode(array $data, HTTPRequest $request): int
    {
        $email = Convert::raw2sql($data['Email'] ?? '');
        if (!$email) {
            return 0;
        }
        $identifierField = Member::config()->get('unique_identifier_field') ?? 'Email';
        $member = Member::get()
            ->filter([$identifierField => $email])
            ->first();

        if ($member) {
            $max = OneTimeCodeLoginHandler::config()->get('max_failed_attempts');
            if ($member->OneTimeCodeFailedAttempts >= $max) {
                return -1;
            }
            $member->generateOneTimeCode();
            // fake the time it takes to send an email
            sleep(rand(0, 2)); // to prevent user enumeration
            $this->SendOneTimeCodeInner($member);
        } else {
            // fake the time it takes to send an email
            sleep(rand(1, 2)); // to prevent user enumeration

        }
        $request->getSession()->set('OneTimeCodeSent', true);
        $request->getSession()->set('OneTimeCodeEmail', $email);
        return 1;
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
