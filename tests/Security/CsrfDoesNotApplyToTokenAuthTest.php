<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The same two endpoints under token authentication — no session middleware,
 * which is the shipped default once Sanctum is installed.
 *
 * Token-authenticated callers cannot be CSRF'd: a browser will not attach a
 * bearer token to a cross-site request. Demanding a CSRF token from them would
 * break every legitimate API client, so the protection must not fire here.
 *
 * Separate class because the middleware stack has to differ, and it is decided
 * before the provider registers routes.
 */
class CsrfDoesNotApplyToTokenAuthTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.api.enabled', true);
        // No session middleware: the stateless API shape.
        $app['config']->set('threat-detection.api.middleware', ['api']);
        $app['config']->set('threat-detection.api.guard', 'none');
        $app['config']->set('threat-detection.api.write_guard', 'none');
        $app['config']->set('threat-detection.enabled', false);
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['cache.default' => 'array']);

        DB::table('threat_logs')->insert([
            'ip_address' => '203.0.113.9', 'url' => 'https://example.com/x', 'user_agent' => 'UA',
            'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
            'confidence_score' => 90, 'confidence_label' => 'very_high', 'action_taken' => 'logged',
            'created_at' => now(), 'updated_at' => now(),
        ]);
    }

    #[Test]
    public function a_stateless_write_needs_no_csrf_token(): void
    {
        $response = $this->postJson('/api/threat-detection/threats/1/false-positive');

        $response->assertStatus(200);
        $this->assertSame(1, DB::table('threat_exclusion_rules')->count(), 'the stateless write was blocked');
    }

    #[Test]
    public function a_stateless_delete_needs_no_csrf_token(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'id' => 1, 'pattern_label' => 'XSS Script Tag', 'path_pattern' => 'x',
            'is_active' => true, 'created_at' => now(), 'updated_at' => now(),
        ]);

        $this->deleteJson('/api/threat-detection/exclusion-rules/1')->assertStatus(200);

        $this->assertSame(0, DB::table('threat_exclusion_rules')->count(), 'the stateless delete was blocked');
    }
}
