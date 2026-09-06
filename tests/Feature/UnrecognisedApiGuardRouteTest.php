<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * An unrecognised api.guard, driven through the real route rather than through
 * the middleware directly.
 *
 * The guard value has to be decided before the provider boots, because that is
 * when it decides whether to append threat-dashboard-auth:api to the route's
 * middleware. Setting it afterwards changes the config and nothing else.
 *
 * What this proves that GuardFailClosedTest cannot: an unrecognised guard is
 * not only refused by the middleware, it also causes the middleware to be
 * attached in the first place. A provider that attached the guard only for
 * values it recognised would leave a typo'd guard wide open — the middleware
 * would never run to refuse anything.
 */
class UnrecognisedApiGuardRouteTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.enabled', false);
        $app['config']->set('threat-detection.api.guard', 'authh');
    }

    #[Test]
    public function a_typo_in_the_api_guard_denies_the_real_read_endpoint(): void
    {
        $this->createThreatLogsTable();

        $this->getJson('/api/threat-detection/stats')->assertStatus(403);
    }

    #[Test]
    public function the_guard_middleware_is_attached_even_though_the_value_is_not_recognised(): void
    {
        $this->assertContains('threat-dashboard-auth:api', config('threat-detection.api.middleware'));
    }
}
