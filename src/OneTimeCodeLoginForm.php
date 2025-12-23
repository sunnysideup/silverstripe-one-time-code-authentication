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
        if ($this->getRequest()->getSession()->get('OneTimeCodeSent')) {
            return FieldList::create([
                FieldGroup::create([
                    TextField::create('OneTimeCode1', '')
                        ->addExtraClass('one-time-code')
                        ->setAttribute('maxlength', '1')
                        ->setAttribute('autocomplete', 'one-time-code')
                        ->setAttribute('autofocus', 'autofocus'),
                    TextField::create('OneTimeCode2', '')
                        ->addExtraClass('one-time-code')
                        ->setAttribute('maxlength', '1')
                        ->setAttribute('autocomplete', 'one-time-code'),
                    TextField::create('OneTimeCode3', '')
                        ->addExtraClass('one-time-code')
                        ->setAttribute('maxlength', '1')
                        ->setAttribute('autocomplete', 'one-time-code'),
                    TextField::create('OneTimeCode4', '')
                        ->addExtraClass('one-time-code')
                        ->setAttribute('maxlength', '1')
                        ->setAttribute('autocomplete', 'one-time-code'),
                    TextField::create('OneTimeCode5', '')
                        ->addExtraClass('one-time-code')
                        ->setAttribute('maxlength', '1')
                        ->setAttribute('autocomplete', 'one-time-code'),
                    TextField::create('OneTimeCode6', '')
                        ->addExtraClass('one-time-code')
                        ->setAttribute('maxlength', '1')
                        ->setAttribute('autocomplete', 'one-time-code'),
                ]),
                LiteralField::create(
                    'Style',
                    '<style>
                        .one-time-code {
                            width: 43px!important;
                            font-size: 18px!important;
                            text-align: center;
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
        }
        else {
            $description = 'A one-time login code will be sent to this email address.';
            if (OneTimeCodeAuthenticator::config()->get('can_login_to_cms') === false) {
                $description .= '<br> Note: CMS users cannot log in using one-time codes.';
            }
            return FieldList::create([
                TextField::create('Email', 'Email Address')
                ->setDescription($description)
            ]);
        }
    }

    protected function getFormActions(): FieldList
    {
        if ($this->getRequest()->getSession()->get('OneTimeCodeSent')) {
            return FieldList::create(
                FormAction::create('doOneTimeCodeLogin', 'Log In')
            );
        }
        else {
            return FieldList::create(
                FormAction::create('doSendOneTimeCode', 'Send Code')
            );
        }
    }
}