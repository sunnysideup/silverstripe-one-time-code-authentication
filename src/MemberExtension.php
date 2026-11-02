<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\Director;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\NumericField;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;

class MemberExtension extends Extension
{
    private static array $db = [
        // Stores a keyed HMAC-SHA256 hash of the code (hex), never the plaintext code.
        'OneTimeCode' => 'Varchar(64)',
        'OneTimeCodeExpiry' => 'Datetime',
        'OneTimeCodeFailedAttempts' => 'Int',
        // Used to rate-limit how often a code can be (re)sent to a member.
        'OneTimeCodeLastSent' => 'Datetime',
    ];

    /**
     * The plaintext code for the current request only (never persisted).
     * Populated by generateOneTimeCode() so it can be emailed/SMSed.
     */
    protected ?string $plainOneTimeCode = null;

    public function afterMemberLoggedIn(): void
    {
        // reset failed attempts on successful login
        $owner = $this->getOwner();
        $owner->OneTimeCodeFailedAttempts = 0;
        $owner->write();
    }

    private static $one_time_code_expiry_minutes = 15;

    private static int $one_time_code_resend_cooldown_seconds = 60;

    private static int $one_time_code_length = 9;

    public function generateOneTimeCode(int $length = 0, int $expiryMinutes = 0): string
    {
        $owner = $this->getOwner();

        if ($length <= 0) {
            $length = (int) $owner->config()->get('one_time_code_length') ?: 9;
        }
        if ($expiryMinutes <= 0) {
            $expiryMinutes = (int) $owner->config()->get('one_time_code_expiry_minutes') ?: 15;
        }
        $oneTimeCode = '';
        for ($i = 0; $i < $length; $i++) {
            $oneTimeCode .= random_int(0, 9);
        }
        $this->plainOneTimeCode = $oneTimeCode;
        $identifierField = Member::config()->get('unique_identifier_field') ?? 'Email';
        $owner->OneTimeCode = $owner->hashOneTimeCode($oneTimeCode, (string) $owner->{$identifierField});
        $owner->OneTimeCodeExpiry = date('Y-m-d H:i:s', time() + ($expiryMinutes * 60));
        $owner->OneTimeCodeLastSent = date('Y-m-d H:i:s');
        $owner->write();
        return $oneTimeCode;
    }

    /**
     * Deterministic, keyed hash of a one-time code so it can be matched via a DB
     * filter while not being stored (or displayed) in plaintext.
     *
     * If an email address is provided, then the hash is bound to that address:
     * the same code hashes differently for a different address.
     * (Capitals and spaces around the address do not matter.)
     */
    public function hashOneTimeCode(string $code, ?string $email = null): string
    {
        if (null !== $email) {
            $code .= '|' . mb_strtolower(trim($email));
        }

        return hash_hmac('sha256', $code, $this->getOneTimeCodeSecret());
    }

    /**
     * When the email address of a member changes, then a code that was sent to the old address
     * must not be usable any more, and the new address must be able to get a code straight away.
     */
    public function onBeforeWrite(): void
    {
        $owner = $this->getOwner();
        $identifierField = Member::config()->get('unique_identifier_field') ?? 'Email';
        if (! $owner->isInDB() || ! $owner->isChanged($identifierField) || $owner->isChanged('OneTimeCode')) {
            return;
        }

        $changes = $owner->getChangedFields(false, DataObject::CHANGE_VALUE);
        $before = mb_strtolower(trim((string) ($changes[$identifierField]['before'] ?? '')));
        $after = mb_strtolower(trim((string) ($changes[$identifierField]['after'] ?? '')));
        if ($before === $after) {
            // only capitals or spaces have changed: same address.
            return;
        }

        $owner->OneTimeCode = null;
        $owner->OneTimeCodeExpiry = '1970-01-01 00:00:00';
        $owner->OneTimeCodeLastSent = null;
        $owner->OneTimeCodeFailedAttempts = 0;
    }

    /**
     * Site-specific secret used to key the code hash. Set SS_ONE_TIME_CODE_SECRET
     * in your environment for the strongest protection; otherwise a stable
     * site-specific fallback is derived so codes are never stored in plaintext.
     */
    protected function getOneTimeCodeSecret(): string
    {
        $secret = Environment::getEnv('SS_ONE_TIME_CODE_SECRET');
        if (! $secret) {
            $secret = 'one-time-code::' . Director::baseFolder();
        }
        return (string) $secret;
    }

    /**
     * Plaintext code for the current request only (for email/SMS templates).
     */
    public function getOneTimeCodePlain(): ?string
    {
        return $this->plainOneTimeCode;
    }

    public function updateCMSFields(FieldList $fields): void
    {
        $owner = $this->getOwner();

        $fields->addFieldsToTab(
            'Root.Security',
            [
                // NB: the live code is intentionally NOT shown here. It is stored
                // hashed and displaying it would allow account impersonation.
                LiteralField::create(
                    'OneTimeCodeExpiryInfo',
                    '<p class="help">The current one-time code (if any) expires at: '
                        . ($owner->OneTimeCodeExpiry ?: 'n/a') . '</p>'
                ),
                NumericField::create('OneTimeCodeFailedAttempts', 'One Time Code Failed Attempts'),
            ]
        );
    }
}
