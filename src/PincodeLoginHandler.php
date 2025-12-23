<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\Email\Email;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Authenticator\LoginHandler;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\LogoutHandler;
use SilverStripe\Security\Security;

class OneTimeCodeLoginHandler extends LoginHandler
{
    private static $allowed_actions = [
        'LoginForm',
    ];

    public function doOneTimeCodeLogin($data, OneTimeCodeLoginForm $form, HTTPRequest $request): HTTPResponse
    {
        $email = $request->getSession()->get('OneTimeCodeEmail');

        $request->getSession()->clear('OneTimeCodeSent');
        $request->getSession()->clear('OneTimeCodeEmail');

        if (!$email) {
            $form->sessionMessage('Session expired.', ValidationResult::TYPE_ERROR);
            return $form->getRequestHandler()->redirectBackToForm();
        }

        $data['Email'] = $email;

        /** @var OneTimeCodeAuthenticator $authenticator */
        $authenticator = Injector::inst()->create(OneTimeCodeAuthenticator::class);
        $member = $authenticator->authenticate($data, $request, $result);
        
        if ($member) {
            if ($result->isValid()) {
                // Absolute redirection URLs may cause spoofing
                $backURL = $this->getBackURL() ?: '/';

                // If a default login dest has been set, redirect to that.
                $backURL = Security::config()->get('default_login_dest') ?: $backURL;

                return $this->redirect($backURL);
            }
            Injector::inst()->get(LogoutHandler::class)->doLogOut($member);
        }
        else {
            $form->sessionMessage('Matching member not found.', ValidationResult::TYPE_ERROR);
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
            $this->sendOneTimeCode($member);

            $request->getSession()->set('OneTimeCodeSent', true);
            $request->getSession()->set('OneTimeCodeEmail', $data['Email'] ?? '');
        }

        $form->sessionMessage('If you entered a registered email address, you will receive a one-time code shortly.', ValidationResult::TYPE_GOOD);

        return $form->getRequestHandler()->redirectBackToForm();
    }

    public function loginForm(): OneTimeCodeLoginForm
    {
        return OneTimeCodeLoginForm::create($this, get_class($this->authenticator), 'LoginForm');
    }

    public function sendOneTimeCode(Member $member): void
    {
        $member->generateOneTimeCode();

        // If SMS sending is implemented, it would go here as an alternative to email.

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