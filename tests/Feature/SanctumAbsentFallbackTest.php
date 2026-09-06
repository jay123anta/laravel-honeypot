<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The Sanctum-absent fallback.
 *
 * The provider strips 'auth:sanctum' from the API middleware when Sanctum is
 * not installed and substitutes plain 'auth'. The substitution is the whole
 * point: an operator who asked for authentication must not end up with an
 * unauthenticated threat-log API because an optional package is missing.
 *
 * This needs its own file rather than living alongside GuardFailClosedTest,
 * because the middleware list has to be decided before the provider boots —
 * and because PHPUnit only collects the class whose name matches the file.
 */
class SanctumAbsentFallbackTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        // What a published config ships with, restored over the base
        // TestCase's simplification.
        $app['config']->set('threat-detection.api.middleware', ['api', 'auth:sanctum']);
        $app['config']->set('threat-detection.api.enabled', true);
        $app['config']->set('threat-detection.enabled', false);
    }

    #[Test]
    public function sanctum_is_genuinely_absent_in_this_test_run(): void
    {
        $this->assertFalse(
            class_exists('Laravel\Sanctum\SanctumServiceProvider'),
            'laravel/sanctum is installed, so this fallback cannot be exercised here'
        );
    }

    #[Test]
    public function the_sanctum_middleware_is_replaced_with_auth_rather_than_simply_dropped(): void
    {
        $middleware = config('threat-detection.api.middleware');

        $this->assertNotContains('auth:sanctum', $middleware, 'auth:sanctum survived without Sanctum installed');
        $this->assertContains('auth', $middleware, 'the API was left unauthenticated when Sanctum was absent');
    }

    #[Test]
    public function the_api_is_not_reachable_unauthenticated_when_sanctum_is_absent(): void
    {
        $this->createThreatLogsTable();

        $response = $this->getJson('/api/threat-detection/stats');

        $this->assertNotSame(
            200,
            $response->getStatusCode(),
            'the API answered an unauthenticated request after the Sanctum fallback'
        );
    }
}
