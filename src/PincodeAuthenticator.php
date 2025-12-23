<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

class PincodeAuthenticator extends MemberAuthenticator
{
    public function supportedServices(): int
    {
        return Authenticator::LOGIN;
    }

    public function authenticate(array $data, HTTPRequest $request, &$result = null): Member|null
    {
        $member = Member::get()
            ->filter([
                Member::config()->get('unique_identifier_field') ?? 'Email' => $data['Email'],
                'Pincode' => $data['Pincode'],
                'PincodeExpiry:GreaterThan' => DBDatetime::now(),
            ])
            ->first();

        if ($member) {
            $member->Pincode = null;
            $member->PincodeExpiry = '1970-01-01 00:00:00';
            $member->write();

            $member->validateCanLogin($result);
            $this->recordLoginAttempt($data, $request, $member, $result->isValid());

            /** @var IdentityStore $identityStore */
            $identityStore = Injector::inst()->get(IdentityStore::class);

            if ($result->isValid()) {
                $identityStore->logIn($member, false, $request);
                $member->registerSuccessfulLogin();
                return $member;
            }
            else {
                $identityStore->logOut();
                $member->registerFailedLogin();
            }
        }

        $result->addError('Invalid email or pincode.');

        return null;
    }

    public function getLoginHandler($link)
    {
        return PincodeLoginHandler::create($link, $this);
    }
}