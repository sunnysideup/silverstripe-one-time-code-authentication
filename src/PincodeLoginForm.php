<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\TextField;
use SilverStripe\Security\LoginForm;

class PincodeLoginForm extends LoginForm
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
        return 'Pincode Login';
    }

    protected function getFormFields(): FieldList
    {
        if ($this->getRequest()->getSession()->get('PincodeSent')) {
            return FieldList::create([
                TextField::create('Pincode', 'Pincode')
            ]);
        }
        else {
            return FieldList::create([
                TextField::create('Email', 'Email Address')
            ]);
        }
    }

    protected function getFormActions(): FieldList
    {
        if ($this->getRequest()->getSession()->get('PincodeSent')) {
            return FieldList::create(
                FormAction::create('doPincodeLogin', 'Log In')
            );
        }
        else {
            return FieldList::create(
                FormAction::create('doSendPincode', 'Send Pincode')
            );
        }
    }
}