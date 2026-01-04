<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use SilverStripe\Security\Permission;

class OneTimeCodeAuthenticator extends MemberAuthenticator
{
    use Configurable;

    private static bool $can_login_to_cms = false;

    public function supportedServices(): int
    {
        return Authenticator::LOGIN;
    }

    public function authenticate(array $data, HTTPRequest $request, &$result = null): Member|null
    {
        $member = Member::get()
            ->filter([
                Member::config()->get('unique_identifier_field') ?? 'Email' => $data['Email'],
                'OneTimeCode' => $data['OneTimeCode'],
                'OneTimeCodeExpiry:GreaterThan' => DBDatetime::now(),
            ])
            ->first();

        if ($member) {
            $member->OneTimeCode = null;
            $member->OneTimeCodeExpiry = '1970-01-01 00:00:00';
            $member->write();

            $member->validateCanLogin($result);
            $this->recordLoginAttempt($data, $request, $member, $result->isValid());

            /** @var IdentityStore $identityStore */
            $identityStore = Injector::inst()->get(IdentityStore::class);

            if ($result->isValid()) {
                if (self::config()->get('can_login_to_cms') || !Permission::checkMember($member, 'CMS_ACCESS')) {
                    $identityStore->logIn($member, false, $request);
                    $member->registerSuccessfulLogin();
                    return $member;
                } else {
                    $result->addError('CMS Users can not use the One Time Code authentication.');
                }
            }
            $identityStore->logOut();
            $member->registerFailedLogin();
        }

        if ($result) {
            $result->addError('Invalid email or code.');
        }

        return null;
    }

    public function getLoginHandler($link)
    {
        return OneTimeCodeLoginHandler::create($link, $this);
    }
}
