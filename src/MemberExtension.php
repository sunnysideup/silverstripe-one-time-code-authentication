<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataExtension;

class MemberExtension extends DataExtension
{
    private static array $db = [
        'OneTimeCode' => 'Varchar(6)',
        'OneTimeCodeExpiry' => 'Datetime',
    ];

    public function generateOneTimeCode(int $length = 6, int $expiryMinutes = 15): void
    {
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
        $fields->removeByName('OneTimeCode');
        $fields->removeByName('OneTimeCodeExpiry');
    }
}