<?php

namespace JayAnta\ThreatDetection;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Services\ConfidenceScorer;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Console\Commands\EnrichThreatLogsCommand;
use JayAnta\ThreatDetection\Console\Commands\ThreatStatsCommand;
use JayAnta\ThreatDetection\Console\Commands\PurgeThreatLogsCommand;

class ThreatDetectionServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Merge configuration
        $this->mergeConfigFrom(
            __DIR__ . '/../config/threat-detection.php',
            'threat-detection'
        );

        // Register supporting services
        $this->app->singleton(ConfidenceScorer::class, fn() => new ConfidenceScorer());
        $this->app->singleton(ExclusionRuleService::class, fn() => new ExclusionRuleService());

        // Register the main service
        $this->app->singleton('threat-detection', function ($app) {
            return new ThreatDetectionService(
                $app->make(ConfidenceScorer::class),
                $app->make(ExclusionRuleService::class)
            );
        });

        $this->app->singleton(ThreatDetectionService::class, function ($app) {
            return $app->make('threat-detection');
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->registerPublishes();
        $this->registerMiddleware();
        $this->registerRoutes();
        $this->registerCommands();
        $this->registerViews();
    }

    /**
     * Register publishable resources.
     */
    protected function registerPublishes(): void
    {
        if ($this->app->runningInConsole()) {
            // Publish config
            $this->publishes([
                __DIR__ . '/../config/threat-detection.php' => config_path('threat-detection.php'),
            ], 'threat-detection-config');

            // Publish migrations
            $this->publishes([
                __DIR__ . '/../database/migrations/create_threat_logs_table.php.stub' => database_path('migrations/' . date('Y_m_d_His') . '_create_threat_logs_table.php'),
                __DIR__ . '/../database/migrations/add_confidence_to_threat_logs_table.php.stub' => database_path('migrations/' . date('Y_m_d_His', time() + 1) . '_add_confidence_to_threat_logs_table.php'),
                __DIR__ . '/../database/migrations/create_threat_exclusion_rules_table.php.stub' => database_path('migrations/' . date('Y_m_d_His', time() + 2) . '_create_threat_exclusion_rules_table.php'),
            ], 'threat-detection-migrations');

            // Publish views (only if views directory exists)
            if (is_dir(__DIR__ . '/../resources/views')) {
                $this->publishes([
                    __DIR__ . '/../resources/views' => resource_path('views/vendor/threat-detection'),
                ], 'threat-detection-views');
            }
        }
    }

    /**
     * Register middleware aliases.
     */
    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('threat-detect', ThreatDetectionMiddleware::class);
    }

    /**
     * Register package routes.
     */
    protected function registerRoutes(): void
    {
        // Register API routes if enabled (skip auth:sanctum if Sanctum is not installed)
        if (config('threat-detection.api.enabled', true)) {
            $middleware = config('threat-detection.api.middleware', ['api', 'auth:sanctum']);

            if (!class_exists(\Laravel\Sanctum\SanctumServiceProvider::class)) {
                $middleware = array_values(array_filter($middleware, fn($m) => $m !== 'auth:sanctum'));
            }

            config(['threat-detection.api.middleware' => $middleware]);

            $this->loadRoutesFrom(__DIR__ . '/../routes/api.php');
        }

        // Register web dashboard routes if enabled and route file exists
        if (config('threat-detection.dashboard.enabled', false)
            && file_exists(__DIR__ . '/../routes/web.php')) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/web.php');
        }
    }

    /**
     * Register console commands.
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                EnrichThreatLogsCommand::class,
                ThreatStatsCommand::class,
                PurgeThreatLogsCommand::class,
            ]);
        }
    }

    /**
     * Register views if the views directory exists.
     */
    protected function registerViews(): void
    {
        if (is_dir(__DIR__ . '/../resources/views')) {
            $this->loadViewsFrom(__DIR__ . '/../resources/views', 'threat-detection');
        }
    }
}
