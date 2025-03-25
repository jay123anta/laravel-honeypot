<?php

namespace Security\Honeypot;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Route;
use Security\Honeypot\Middleware\HoneypotMiddleware;
use Security\Honeypot\Services\HoneypotService;
use Security\Honeypot\Commands\BanIpCommand;
use Security\Honeypot\Commands\UnbanIpCommand;

class HoneypotServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any package services.
     */
    public function boot()
    {
        // 📌 Load package routes
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');

        // 📌 Load migrations
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        // 📌 Load views with namespace 'honeypot'
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'honeypot');

        // 📦 Publish config file
        $this->publishes([
            __DIR__.'/../config/honeypot.php' => config_path('honeypot.php'),
        ], 'honeypot-config');

        // 📦 Publish views
        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/honeypot'),
        ], 'honeypot-views');

        // 📦 Publish migrations
        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'honeypot-migrations');

        // 🛡️ Register middleware alias for easy use in kernel/routes
        $this->app['router']->aliasMiddleware('honeypot', HoneypotMiddleware::class);

        // 🛠️ Register Artisan CLI commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                BanIpCommand::class,
                UnbanIpCommand::class,
            ]);
        }
    }

    /**
     * Register any application services.
     */
    public function register()
    {
        // 🔗 Merge default config to allow publishing override
        $this->mergeConfigFrom(
            __DIR__.'/../config/honeypot.php', 'honeypot'
        );

        // 🔧 Bind HoneypotService in the container (use bind if service depends on request context)
        $this->app->bind(HoneypotService::class, function ($app) {
            return new HoneypotService();
        });
    }
}
