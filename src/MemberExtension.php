<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\Control\Director;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\NumericField;

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
        $this->owner->OneTimeCodeFailedAttempts = 0;
        $this->owner->write();
    }

    private static $one_time_code_expiry_minutes = 15;

    private static int $one_time_code_resend_cooldown_seconds = 60;

    private static int $one_time_code_length = 9;

    public function generateOneTimeCode(int $length = 0, int $expiryMinutes = 0): string
    {
        if ($length <= 0) {
            $length = (int) $this->getOwner()->config()->get('one_time_code_length') ?: 9;
        }
        if ($expiryMinutes <= 0) {
            $expiryMinutes = (int) $this->getOwner()->config()->get('one_time_code_expiry_minutes') ?: 15;
        }
        $oneTimeCode = '';
        for ($i = 0; $i < $length; $i++) {
            $oneTimeCode .= random_int(0, 9);
        }
        $this->plainOneTimeCode = $oneTimeCode;
        // Persist only a hash so the live code cannot be read from the DB (or CMS).
        $this->owner->OneTimeCode = $this->owner->hashOneTimeCode($oneTimeCode);
        $this->owner->OneTimeCodeExpiry = date('Y-m-d H:i:s', time() + ($expiryMinutes * 60));
        $this->owner->OneTimeCodeLastSent = date('Y-m-d H:i:s');
        $this->owner->write();
        return $oneTimeCode;
    }

    /**
     * Deterministic, keyed hash of a one-time code so it can be matched via a DB
     * filter while not being stored (or displayed) in plaintext.
     */
    public function hashOneTimeCode(string $code): string
    {
        return hash_hmac('sha256', $code, $this->getOneTimeCodeSecret());
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
        $fields->addFieldsToTab(
            'Root.Security',
            [
                // NB: the live code is intentionally NOT shown here. It is stored
                // hashed and displaying it would allow account impersonation.
                LiteralField::create(
                    'OneTimeCodeExpiryInfo',
                    '<p class="help">The current one-time code (if any) expires at: '
                        . ($this->owner->OneTimeCodeExpiry ?: 'n/a') . '</p>'
                ),
                NumericField::create('OneTimeCodeFailedAttempts', 'One Time Code Failed Attempts'),
            ]
        );
    }
}
