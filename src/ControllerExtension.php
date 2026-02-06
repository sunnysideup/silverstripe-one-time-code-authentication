<?php

declare(strict_types=1);

namespace Sunnysideup\OneTimeCode;

use SilverStripe\CMS\Controllers\ContentController;
use SilverStripe\Core\Extension;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Security;

/**
 * Class \Sunnysideup\OneTimeCode\\ControllerExtension
 *
 * @property ContentController|ControllerExtension $owner
 */
class ControllerExtension extends Extension
{
    private static $allowed_actions = [
        'OneTimeCodeLoginForm',
    ];

    public function OneTimeCodeLoginForm()
    {
        $controller = Injector::inst()->get(Security::class);
        return Injector::inst()->get(OneTimeCodeAuthenticator::class)
            ->getLoginHandler($controller->Link('login/onetimecode'))
            ->loginForm();
    }
}
