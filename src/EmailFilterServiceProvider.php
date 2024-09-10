<?php

namespace FunnyDev\EmailFilter;

use Exception;
use Illuminate\Foundation\Console\VendorPublishCommand;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;

class EmailFilterServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any package services.
     *
     * @return void
     */
    public function boot(Router $router): void
    {
        $this->publishes([
            __DIR__ . '/../config/email-filter.php' => config_path('email-filter.php'),
            __DIR__.'/../app/Http/Controllers/EmailFilterController.php' => app_path('Http/Controllers/EmailFilterController.php'),
        ], 'email-filter');

        try {
            if (!file_exists(config_path('email-filter.php'))) {
                $this->commands([
                    VendorPublishCommand::class,
                ]);

                Artisan::call('vendor:publish', ['--provider' => 'FunnyDev\\EmailFilter\\EmailFilterServiceProvider', '--tag' => ['email-filter']]);
            }
        } catch (Exception $e) {}
    }

    /**
     * Register any package services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/email-filter.php', 'email-filter'
        );
        $this->app->singleton(EmailFilterSdk::class, function ($app) {
            $tld = $app['config']['email-filter.tld'];
            return new EmailFilterSdk($tld);
        });
    }
}
