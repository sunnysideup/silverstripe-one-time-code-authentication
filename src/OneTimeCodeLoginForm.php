<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Forms\FieldGroup;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\TextField;
use SilverStripe\Security\LoginForm;

class OneTimeCodeLoginForm extends LoginForm
{
    public function __construct(
        $controller,
        $authenticatorClass,
        $name,
        $fields = null,
        $actions = null,
        $checkCurrentUser = true
    ) {
        $this->setController($controller);
        $this->setAuthenticatorClass($authenticatorClass);
        if (!$fields) {
            $fields = $this->getFormFields();
        }
        if (!$actions) {
            $actions = $this->getFormActions();
        }
        $request = $controller?->getRequest();
        $session = $request?->getSession();
        $backURL = $controller->getRequest()->getVar('BackURL');
        if ($backURL && $session && $request) {
            $session->set('OneTimeCodeBackURL', $backURL);
        }
        // Reduce attack surface by enforcing POST requests
        $this->setFormMethod('POST', true);

        parent::__construct($controller, $name, $fields, $actions);
    }

    public function getAuthenticatorName(): string
    {
        return 'One Time Code';
    }

    protected function getFormFields(): FieldList
    {
        if ($this->codeSent()) {
            $fields = [];

            for ($i = 1; $i <= 6; $i++) {
                $field = TextField::create('OneTimeCode' . $i, '')
                    ->addExtraClass('one-time-code')
                    ->setAttribute('maxlength', '1')
                    ->setAttribute('autocomplete', 'one-time-code');

                if ($i === 1) {
                    $field->setAttribute('autofocus', 'autofocus');
                }

                $fields[] = $field;
            }

            $group = FieldGroup::create($fields)
                ->addExtraClass('one-time-code-group');
            return FieldList::create([
                $group,
                LiteralField::create(
                    'Style',
                    '<style>
                        .one-time-code {
                            width: 43px!important;
                            font-size: 18px!important;
                            text-align: center;
                        }
                        .one-time-code-group {
                            display: flex;
                            gap: 8px;
                        }
                    </style>
                    <script>
                        const inputs = document.querySelectorAll(\'input.one-time-code\');
                        const firstInput = document.querySelector(\'input.one-time-code\');

                        inputs.forEach((input, index) => {
                            input.addEventListener(\'input\', (e) => {
                                if (input.value.length === input.maxLength && index < inputs.length - 1) {
                                inputs[index + 1].focus();
                                }
                            });

                            input.addEventListener(\'keydown\', (e) => {
                                if (e.key === \'Backspace\' && input.value.length === 0 && index > 0) {
                                    inputs[index - 1].focus();
                                }
                            });

                            input.addEventListener(\'input\', () => {
                                const allFilled = Array.from(inputs).every(i => i.value.length === i.maxLength);
                                if (allFilled) {
                                    input.form.submit();
                                }
                            });
                        });

                        // auto focus first input on page load
                        window.addEventListener(\'load\', () => {
                            if (firstInput) {
                                firstInput.focus();
                            }
                        });

                        // allow pasting full code into first input
                        firstInput.addEventListener(\'paste\', (e) => {
                            const pasteData = e.clipboardData.getData(\'text\').trim();
                            if (pasteData.length === inputs.length) {
                                inputs.forEach((input, index) => {
                                    input.value = pasteData.charAt(index);
                                });
                                e.preventDefault();
                                firstInput.form.submit();
                            }
                        });
                    </script>
                    '
                )
            ]);
        } else {
            if (OneTimeCodeLoginHandler::config()->get('send_with_sms')) {
                $description = _t(__CLASS__ . '.SMS_DESCRIPTION', 'A one-time login code will be sent to the phone number associated with this account.');
            } else {
                $description = _t(__CLASS__ . '.EMAIL_DESCRIPTION', 'A one-time login code will be sent to this email address.');
            }
            if (OneTimeCodeAuthenticator::config()->get('can_login_to_cms') === false) {
                $description .= '<br>' . _t(__CLASS__ . '.CMS_USERS_CANNOT_LOGIN', 'CMS users cannot log in using one-time codes.');
            }
            return FieldList::create([
                TextField::create(
                    'Email',
                    _t(__CLASS__ . '.EMAIL_LABEL', 'Please enter your email address')
                )
                    ->setAttribute('aria-describedby', 'description')
                    ->setAttribute('autocomplete', 'email')
                    ->setAttribute('required', 'required')
                    ->setDescription($description)
            ]);
        }
    }

    protected function getFormActions(): FieldList
    {
        if ($this->codeSent()) {
            return FieldList::create(
                FormAction::create('doOneTimeCodeLogin', 'Log In')
            );
        } else {
            return FieldList::create(
                FormAction::create('doSendOneTimeCode', 'Send Code')
            );
        }
    }

    protected function codeSent(): bool
    {
        return (bool) $this->getRequest()->getSession()->get('OneTimeCodeSent');
    }
}
