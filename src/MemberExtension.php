<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataExtension;

class MemberExtension extends DataExtension
{
    private static array $db = [
        'Pincode' => 'Varchar(6)',
        'PincodeExpiry' => 'Datetime',
    ];

    public function generatePincode(int $length = 6, int $expiryMinutes = 15): void
    {
        $pincode = '';
        for ($i = 0; $i < $length; $i++) {
            $pincode .= random_int(0, 9);
        }
        $this->owner->Pincode = $pincode;
        $this->owner->PincodeExpiry = date('Y-m-d H:i:s', time() + ($expiryMinutes * 60));
        $this->owner->write();
    }

    public function updateCMSFields(FieldList $fields): void
    {
        $fields->removeByName('Pincode');
        $fields->removeByName('PincodeExpiry');
    }
}