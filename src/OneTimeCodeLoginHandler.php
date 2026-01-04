<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\Email\Email;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Authenticator\LoginHandler;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\LogoutHandler;
use SilverStripe\Security\Permission;
use SilverStripe\Security\Security;

class OneTimeCodeLoginHandler extends LoginHandler
{
    use Configurable;

    private static int $max_failed_attempts = 10;
    private static bool $send_with_sms = false;

    private static $allowed_actions = [
        'LoginForm',
    ];

    public function doOneTimeCodeLogin($data, OneTimeCodeLoginForm $form, HTTPRequest $request): HTTPResponse
    {
        $email = Convert::raw2sql($request->getSession()->get('OneTimeCodeEmail') ?? '');

        if (!$email) {
            $form->sessionMessage('Session expired.', ValidationResult::TYPE_ERROR);
            $request->getSession()->clear('OneTimeCodeSent');
            $request->getSession()->clear('OneTimeCodeEmail');
            return $form->getRequestHandler()->redirectBackToForm();
        }

        $data['Email'] = $email;

        //put together one time code from six front-end fields
        $oneTimeCode = '';
        for ($i = 1; $i <= 6; ++$i) {
            $oneTimeCodePart = $data['OneTimeCode' . $i] ?? '';
            $oneTimeCode .= $oneTimeCodePart;
        }
        $data['OneTimeCode'] = $oneTimeCode;

        // just get member by email to increment failed attempts
        $identifierField = Member::config()->get('unique_identifier_field') ?? 'Email';
        $memberByEmail = $email ? Member::get()
            ->filter([$identifierField => $email])
            ->first() : null;

        if ($memberByEmail && $memberByEmail->OneTimeCodeFailedAttempts >= self::config()->get('max_failed_attempts')) {
            $form->sessionMessage('Too many failed attempts to log in using one-time codes. Please log in using your email and password.', ValidationResult::TYPE_ERROR);
            $request->getSession()->clear('OneTimeCodeSent');
            $request->getSession()->clear('OneTimeCodeEmail');
            return $form->getRequestHandler()->redirectBackToForm();
        }

        /** @var OneTimeCodeAuthenticator $authenticator */
        $authenticator = Injector::inst()->create(OneTimeCodeAuthenticator::class);
        /**  @var  ValidationResult|null $result */
        $member = $authenticator->authenticate($data, $request, $result);

        if ($member) {
            if ($result && $result->isValid()) {
                // Absolute redirection URLs may cause spoofing
                $backURL = $this->getBackURL() ?: '/';

                // If a default login dest has been set, redirect to that.
                $backURL = Security::config()->get('default_login_dest') ?: $backURL;

                $request->getSession()->clear('OneTimeCodeSent');
                $request->getSession()->clear('OneTimeCodeEmail');
                return $this->redirect($backURL);
            }
            Injector::inst()->get(LogoutHandler::class)->doLogOut($member);
        } else {
            $form->sessionMessage('Invalid one-time code.', ValidationResult::TYPE_ERROR);
        }

        if ($memberByEmail) {
            $memberByEmail->OneTimeCodeFailedAttempts += 1;
            $memberByEmail->write();
        }

        return $form->getRequestHandler()->redirectBackToForm();
    }

    public function doSendOneTimeCode($data, OneTimeCodeLoginForm $form, HTTPRequest $request): HTTPResponse
    {
        $identifierField = Member::config()->get('unique_identifier_field') ?? 'Email';
        $member = Member::get()
            ->filter([$identifierField => $data['Email'] ?? false])
            ->first();

        if ($member) {
            if ($member->OneTimeCodeFailedAttempts >= self::config()->get('max_failed_attempts')) {
                $form->sessionMessage('Too many failed attempts to log in using one-time codes. Please log in using your email and password.', ValidationResult::TYPE_ERROR);
                return $form->getRequestHandler()->redirectBackToForm();
            }
            $this->sendOneTimeCode($member);
        }

        $request->getSession()->set('OneTimeCodeSent', true);
        $request->getSession()->set('OneTimeCodeEmail', $data['Email'] ?? '');

        $form->sessionMessage('Please check your email for code and enter code below. ', ValidationResult::TYPE_GOOD);

        return $form->getRequestHandler()->redirectBackToForm();
    }

    public function loginForm(): OneTimeCodeLoginForm
    {
        return OneTimeCodeLoginForm::create($this, get_class($this->authenticator), 'LoginForm');
    }

    public function sendOneTimeCode(Member $member): void
    {
        $member->generateOneTimeCode();

        if (self::config()->get('send_with_sms')) {
            // SMS integration is site-specific and must be implemented by the user.
            $this->extend('updateSendOneTimeCodeViaSMS', $member);
        } else {
            $email = Email::create()
                ->setHTMLTemplate('Sunnysideup\\OneTimeCode\\Email\\OneTimeCodeLoginEmail')
                ->setData($member)
                ->setSubject('Your login one-time code')
                ->setTo($member->Email);
            if ($member->isInDB()) {
                $email->send();
            }
        }
    }
}
