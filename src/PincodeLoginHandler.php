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

class PincodeLoginHandler extends LoginHandler
{
    private static $allowed_actions = [
        'LoginForm',
    ];

    public function doPincodeLogin($data, PincodeLoginForm $form, HTTPRequest $request): HTTPResponse
    {
        $email = $request->getSession()->get('PincodeEmail');

        $request->getSession()->clear('PincodeSent');
        $request->getSession()->clear('PincodeEmail');

        if (!$email) {
            $form->sessionMessage('Session expired.', ValidationResult::TYPE_ERROR);
            return $form->getRequestHandler()->redirectBackToForm();
        }

        $data['Email'] = $email;

        /** @var PincodeAuthenticator $authenticator */
        $authenticator = Injector::inst()->create(PincodeAuthenticator::class);
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
    
    public function doSendPincode($data, PincodeLoginForm $form, HTTPRequest $request): HTTPResponse
    {
        $identifierField = Member::config()->get('unique_identifier_field') ?? 'Email';
        $member = Member::get()
            ->filter([$identifierField => $data['Email'] ?? false])
            ->first();

        if ($member) {
            $this->sendPincode($member);

            $request->getSession()->set('PincodeSent', true);
            $request->getSession()->set('PincodeEmail', $data['Email'] ?? '');
        }

        $form->sessionMessage('If you entered a registered email address, you will receive a pincode shortly.', ValidationResult::TYPE_GOOD);

        return $form->getRequestHandler()->redirectBackToForm();
    }

    public function loginForm(): PincodeLoginForm
    {
        return PincodeLoginForm::create($this, get_class($this->authenticator), 'LoginForm');
    }

    public function sendPincode(Member $member): void
    {
        $member->generatePincode();

        // If SMS sending is implemented, it would go here as an alternative to email.

        $email = Email::create()
            ->setHTMLTemplate('Sunnysideup\\OneTimeCode\\Email\\PincodeLoginEmail')
            ->setData($member)
            ->setSubject('Your login pincode')
            ->setTo($member->Email);
        if ($member->isInDB()) {
            $email->send();
        }
    }
}