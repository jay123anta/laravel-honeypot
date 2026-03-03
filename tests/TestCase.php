<?php

namespace JayAnta\ThreatDetection\Tests;

use Orchestra\Testbench\TestCase as OrchestraTestCase;
use JayAnta\ThreatDetection\ThreatDetectionServiceProvider;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [ThreatDetectionServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('threat-detection.enabled', true);
        $app['config']->set('threat-detection.enabled_environments', null);
        $app['config']->set('threat-detection.table_name', 'threat_logs');
        $app['config']->set('threat-detection.whitelisted_ips', []);
        $app['config']->set('threat-detection.dashboard.enabled', false);
        $app['config']->set('threat-detection.api.enabled', true);
        $app['config']->set('threat-detection.api.middleware', ['api']);
    }

    protected function createThreatLogsTable(): void
    {
        Schema::create(config('threat-detection.table_name', 'threat_logs'), function (Blueprint $table) {
            $table->id();
            $table->string('ip_address')->index();
            $table->text('url');
            $table->text('user_agent')->nullable();
            $table->text('type');
            $table->text('payload')->nullable();
            $table->string('threat_level')->default('medium')->index();
            $table->string('action_taken')->default('logged');
            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->string('country_code', 5)->nullable()->index();
            $table->string('country_name', 100)->nullable();
            $table->string('city', 100)->nullable();
            $table->string('isp', 255)->nullable();
            $table->string('cloud_provider', 50)->nullable()->index();
            $table->boolean('is_foreign')->default(false)->index();
            $table->boolean('is_cloud_ip')->default(false)->index();
            $table->timestamps();
        });
    }
}
