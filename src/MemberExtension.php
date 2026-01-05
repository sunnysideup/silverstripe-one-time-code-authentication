<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\TextField;
use SilverStripe\Core\Extension;

class MemberExtension extends Extension
{
    private static array $db = [
        'OneTimeCode' => 'Varchar(6)',
        'OneTimeCodeExpiry' => 'Datetime',
        'OneTimeCodeFailedAttempts' => 'Int',
    ];

    public function afterMemberLoggedIn(): void
    {
        // reset failed attempts on successful login
        $this->owner->OneTimeCodeFailedAttempts = 0;
        $this->owner->write();
    }

    private static $one_time_code_expiry_minutes = 15;

    public function generateOneTimeCode(int $length = 6, int $expiryMinutes = 0): void
    {
        if ($expiryMinutes <= 0) {
            $expiryMinutes = $this->getOwner()->get('one_time_code_expiry_minutes') ?: 15;
        }
        $oneTimeCode = '';
        for ($i = 0; $i < $length; $i++) {
            $oneTimeCode .= random_int(0, 9);
        }
        $this->owner->OneTimeCode = $oneTimeCode;
        $this->owner->OneTimeCodeExpiry = date('Y-m-d H:i:s', time() + ($expiryMinutes * 60));
        $this->owner->write();
    }

    public function updateCMSFields(FieldList $fields): void
    {
        $fields->addFieldsToTab(
            'Root.Security',
            [
                ReadonlyField::create('OneTimeCode', 'One Time Code'),
                LiteralField::create(
                    'OneTimeCodeExpiryInfo',
                    '<p class="help">The one-time code expires at: ' . ($this->owner->OneTimeCodeExpiry ?? 'n/a') . '</p>'
                ),
                TextField::create('OneTimeCodeFailedAttempts', 'One Time Code Failed Attempts'),
            ]
        );
    }
}
