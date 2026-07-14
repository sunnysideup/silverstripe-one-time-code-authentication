<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Authenticator\LoginHandler;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\LogoutHandler;
use SilverStripe\Security\Security;

class OneTimeCodeLoginHandler extends LoginHandler
{
    use Configurable;

    private static int $max_failed_attempts = 10;

    private static $allowed_actions = [
        'LoginForm',
    ];

    /**
     * Return the MemberLoginForm form
     *
     * @return OneTimeCodeLoginForm
     */
    public function loginForm()
    {
        return OneTimeCodeLoginForm::create(
            $this,
            get_class($this->authenticator),
            'LoginForm'
        );
    }

    public function doOneTimeCodeLogin($data, OneTimeCodeLoginForm $form, HTTPRequest $request): HTTPResponse
    {
        $session = $request->getSession();

        $email = Convert::raw2sql($request->getSession()->get('OneTimeCodeEmail') ?? '');

        if (! $email) {
            $form->sessionMessage('Session expired.', ValidationResult::TYPE_ERROR);
            $request->getSession()->clear('OneTimeCodeSent');
            $request->getSession()->clear('OneTimeCodeEmail');
            return $form->getRequestHandler()->redirectBackToForm();
        }

        $data['Email'] = $email;

        //put together one time code from the individual front-end fields
        $codeLength = (int) Member::config()->get('one_time_code_length') ?: 9;
        $oneTimeCode = '';
        for ($i = 1; $i <= $codeLength; ++$i) {
            $oneTimeCodePart = $data['OneTimeCode' . $i] ?? '';
            $oneTimeCode .= $oneTimeCodePart;
        }
        $data['OneTimeCode'] = $oneTimeCode;

        // just get member by email to increment failed attempts
        $identifierField = Member::config()->get('unique_identifier_field') ?? 'Email';
        $memberByEmail = $email ? Member::get()
            ->filter([$identifierField => $email])
            ->first() : null;

        $max = self::config()->get('max_failed_attempts');
        if ($memberByEmail && $memberByEmail->OneTimeCodeFailedAttempts >= $max) {
            // Use the same generic message as an invalid code so that a locked
            // account cannot be distinguished from an unknown email (enumeration).
            $form->sessionMessage(
                _t(__CLASS__ . '.INVALID_CODE_MESSAGE', 'Invalid one-time code.'),
                ValidationResult::TYPE_ERROR
            );
            $session->clear('OneTimeCodeSent');
            $session->clear('OneTimeCodeEmail');
            return $form->getRequestHandler()->redirectBackToForm();
        }

        /** @var OneTimeCodeAuthenticator $authenticator */
        $authenticator = Injector::inst()->create(OneTimeCodeAuthenticator::class);
        /** @var ValidationResult|null $result */
        $result = ValidationResult::create();
        $member = $authenticator->authenticate($data, $request, $result);
        if ($member && $member instanceof Member) {
            if ($result && $result->isValid()) {
                // Absolute/off-site redirection URLs may cause spoofing, so only
                // honour the stored BackURL if it points at this site.
                $backURL = $session->get('OneTimeCodeBackURL');
                if (! $backURL || ! Director::is_site_url($backURL)) {
                    $backURL = $this->getBackURL() ?: '/';

                    // If a default login dest has been set, redirect to that.
                    $backURL = Security::config()->get('default_login_dest') ?: $backURL;
                }

                $session->clear('OneTimeCodeSent');
                $session->clear('OneTimeCodeBackURL');
                $session->clear('OneTimeCodeEmail');
                return $this->redirect($backURL);
            }

            Injector::inst()->get(LogoutHandler::class)->doLogOut($member);
            $form->sessionMessage(
                _t(__CLASS__ . '.INVALID_CODE_MESSAGE', 'Invalid one-time code.'),
                ValidationResult::TYPE_ERROR
            );
        } else {
            $form->sessionMessage(
                _t(__CLASS__ . '.INVALID_CODE_MESSAGE', 'Invalid one-time code.'),
                ValidationResult::TYPE_ERROR
            );
        }

        if ($memberByEmail) {
            $memberByEmail->OneTimeCodeFailedAttempts += 1;
            $memberByEmail->write();
        }
        $form->setSessionValidationResult($result);
        return $form->getRequestHandler()->redirectBackToForm();
    }

    public function doSendOneTimeCode($data, OneTimeCodeLoginForm $form, HTTPRequest $request): HTTPResponse
    {
        // Always show the same neutral message regardless of whether the email
        // matches an account, is rate-limited, or is locked out. This prevents
        // account enumeration via the send-code response.
        Injector::inst()->get(OneTimeCodeApi::class)->sendOneTimeCode($data, $request);
        $form->sessionMessage(
            _t(__CLASS__ . '.ENTER_CODE_MESSAGE', 'If an account matches that email address, a one-time code has been sent. Please enter it below.'),
            ValidationResult::TYPE_GOOD
        );
        return $form->getRequestHandler()->redirectBackToForm();
    }
}
