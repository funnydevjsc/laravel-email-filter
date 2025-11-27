# Email Filter Laravel

The free Laravel package to help you filter your users email with multiple services

## Use Cases

- Perform a powerful checking for user email before approving registration or invoice making.
- Parse result from validator
- Example use case

## Features

- Check blacklist from poste.io, site24x7.com
- Check quality from maxmind.com, apivoid.com, ipqualityscore.com
- Easy to validate with a simple line code

## Requirements

- **PHP**: 8.1 or higher
- **Laravel** 9.0 or higher

## Quick Start

If you prefer to install this package into your own Laravel application, please follow the installation steps below

## Installation

#### Step 1. Install a Laravel project if you don't have one already

https://laravel.com/docs/installation

#### Step 2. Require the current package using composer:

```bash
composer require funnydevjsc/laravel-email-filter
```

#### Step 3. Publish the controller file and config file

```bash
php artisan vendor:publish --provider="FunnyDev\EmailFilter\EmailFilterServiceProvider" --tag="email-filter"
```

If publishing files fails, please create corresponding files at the path `config/email-filter.php` and `app\Http\Controllers\EmailFilterControllers.php` from this package. And you can also further customize the EmailFilterControllers.php file to suit your project.

#### Step 4. Update the various config settings in the published config file:

After publishing the package assets a configuration file will be located at <code>config/email-filter.php</code>.

<!--- ## Usage --->

## Testing

``` php
<?php

namespace App\Console\Commands;

use FunnyDev\EmailFilter\EmailFilterSdk;
use Illuminate\Console\Command;

class EmailFilterTestCommand extends Command
{
    protected $signature = 'email-filter:test';

    protected $description = 'Test EmailFilter SDK';

    public function __construct()
    {
        parent::__construct();
    }

    public function handle()
    {
        $instance = new EmailFilterSdk();
        
        // Perform checking with fast mode turned on and only use $result['recommended'] as signal (true/false)
        $result = $instance->validate(email: 'testing@example.comB3Kin7YM', fast: true, score: false);
        
        // Perform a full checking
        $result = $instance->validate(email: 'f*cking@example.comB3Kin7YM', fast: false, score: true);
        
        // Explanation of results
        $result = [
            'query' => $email,
            'recommend' => true, // Recommended value of whether to accept this email or not
            'reason' => '', // Reason why the email is not recommended
            'trustable' => [
                'exist' => true, // Does the email exist
                'disposable' => false, // Is the email spam
                'blacklist' => 0, // Percentage of blacklists as a float
                'fraud_score' => 0, // Fraud score on a 100-point scale
                'suspicious' => false, // Is the email suspicious of maliciousness
                'high_risk' => false, // Is the email considered high risk of payment
                'domain_type' => 'popular',
                'domain_trust' => true, // Is the domain name trustworthy?
                'domain_age' => '',
                'dns_valid' => false, // Does DNS match between domain name and SMTP server?
                'username' => true // Is the email address username trustworthy?
            ]
        ];
    }
}
```

## Feedback

Respect us in the [Laravel Việt Nam](https://www.facebook.com/groups/167363136987053)

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

### Security

If you discover any security related issues, please email contact@funnydev.vn or use the issue tracker.

## Credits

- [Funny Dev., Jsc](https://github.com/funnydevjsc)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
