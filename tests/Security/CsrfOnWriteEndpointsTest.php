<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD-008 — the write endpoints accept cross-origin cookie-authenticated
 * requests.
 *
 * The two write routes disable detection. Marking a threat as a false positive
 * creates an exclusion rule; deleting an exclusion rule removes one. Both
 * change what the detector reports for *everyone*, permanently, and neither
 * shows up as an attack afterwards — an attacker who can reach them turns the
 * alarm off rather than tripping it.
 *
 * They live in Laravel's `api` group, which is stateless by design and carries
 * no VerifyCsrfToken. That is correct for token authentication. It stops being
 * correct the moment the endpoints are reached with cookies, which is what the
 * Sanctum-absent fallback produces: the provider substitutes the session-based
 * `auth` middleware, and an application that wants a browser-usable dashboard
 * adds session middleware to reach it.
 *
 * This file drives that configuration specifically. An earlier version of this
 * test used Auth::login() inside the plain `api` group, which authenticates
 * without a session at all — it demonstrated the missing middleware but not the
 * attack, and no session-aware fix could have made it pass. Sessions here are
 * real.
 */
class CsrfOnWriteEndpointsTest extends TestCase
{
    /**
     * The realistic vulnerable shape: the API reachable with cookies, because
     * the operator wanted the dashboard to work and Sanctum is not installed.
     * VerifyCsrfToken is deliberately absent — that is the finding.
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.api.enabled', true);
        $app['config']->set('threat-detection.api.middleware', ['api', StartSession::class]);
        $app['config']->set('threat-detection.api.guard', 'none');
        $app['config']->set('threat-detection.api.write_guard', 'role');
        $app['config']->set('threat-detection.api.role', 'admin');
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

        DB::table('threat_exclusion_rules')->insert([
            'id' => 1, 'pattern_label' => 'XSS Script Tag', 'path_pattern' => 'x',
            'is_active' => true, 'created_at' => now(), 'updated_at' => now(),
        ]);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function loginAsAdmin(): void
    {
        Auth::login(new ApiUser(['admin']));
    }

    private function rulesCount(): int
    {
        return DB::table('threat_exclusion_rules')->count();
    }

    // ── positive control: the dashboard's own request still works ──────────

    /**
     * The shipped dashboard fetches with credentials: 'same-origin' and an
     * X-CSRF-TOKEN header read from the meta tag. If that stops working the
     * fix is worse than the bug, so it is asserted first and separately.
     */
    #[Test]
    public function the_dashboards_own_false_positive_request_still_succeeds(): void
    {
        $this->loginAsAdmin();

        $response = $this->withSession(['_token' => 'dashboard-token'])
            ->post(
                '/api/threat-detection/threats/1/false-positive',
                [],
                ['X-CSRF-TOKEN' => 'dashboard-token']
            );

        $response->assertStatus(200);
        $this->assertSame(2, $this->rulesCount(), 'the legitimate write did not create its exclusion rule');
    }

    #[Test]
    public function the_dashboards_own_delete_request_still_succeeds(): void
    {
        $this->loginAsAdmin();

        $response = $this->withSession(['_token' => 'dashboard-token'])
            ->delete(
                '/api/threat-detection/exclusion-rules/1',
                [],
                ['X-CSRF-TOKEN' => 'dashboard-token']
            );

        $response->assertStatus(200);
        $this->assertSame(0, $this->rulesCount(), 'the legitimate delete did not remove the rule');
    }

    /** A form-style _token field is accepted as well as the header. */
    #[Test]
    public function a_form_token_field_is_accepted_as_well_as_the_header(): void
    {
        $this->loginAsAdmin();

        $this->withSession(['_token' => 'form-token'])
            ->post('/api/threat-detection/threats/1/false-positive', ['_token' => 'form-token'])
            ->assertStatus(200);

        $this->assertSame(2, $this->rulesCount());
    }

    // ── negative: cross-origin, cookie-authenticated, no token ─────────────

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function writeEndpoints(): array
    {
        return [
            'mark false positive' => ['POST', '/api/threat-detection/threats/1/false-positive'],
            'delete exclusion rule' => ['DELETE', '/api/threat-detection/exclusion-rules/1'],
        ];
    }

    #[Test]
    #[DataProvider('writeEndpoints')]
    public function a_session_authenticated_write_without_a_token_is_rejected(string $method, string $uri): void
    {
        $this->loginAsAdmin();
        $before = $this->rulesCount();

        $response = $this->withSession(['_token' => 'real-token'])->call(
            $method,
            $uri,
            [],
            [],
            [],
            ['HTTP_ORIGIN' => 'https://evil.example', 'HTTP_REFERER' => 'https://evil.example/page']
        );

        $this->assertGreaterThanOrEqual(400, $response->getStatusCode(), 'a tokenless write was accepted');
        $this->assertSame($before, $this->rulesCount(), 'a tokenless write changed the exclusion rules');
    }

    #[Test]
    #[DataProvider('writeEndpoints')]
    public function a_session_authenticated_write_with_the_wrong_token_is_rejected(string $method, string $uri): void
    {
        $this->loginAsAdmin();
        $before = $this->rulesCount();

        $response = $this->withSession(['_token' => 'real-token'])->call(
            $method,
            $uri,
            [],
            [],
            [],
            ['HTTP_X_CSRF_TOKEN' => 'attacker-guess']
        );

        $this->assertGreaterThanOrEqual(400, $response->getStatusCode(), 'a write with a wrong token was accepted');
        $this->assertSame($before, $this->rulesCount());
    }

    /**
     * The exclusion-rule delete is the highest-value target of the two: it
     * removes a rule silently and there is no record afterwards that anything
     * happened. Called out on its own so it cannot be lost in a data provider.
     */
    #[Test]
    public function a_cross_origin_delete_cannot_silently_remove_an_exclusion_rule(): void
    {
        $this->loginAsAdmin();

        $this->assertSame(1, $this->rulesCount(), 'no rule to delete, so this proves nothing');

        $this->withSession(['_token' => 'real-token'])
            ->call('DELETE', '/api/threat-detection/exclusion-rules/1', [], [], [],
                ['HTTP_ORIGIN' => 'https://evil.example']);

        $this->assertSame(1, $this->rulesCount(), 'a cross-origin request deleted an exclusion rule');
    }

    // ── reads are unaffected ───────────────────────────────────────────────

    /**
     * CSRF applies to the writes only. A GET that changes nothing must not
     * start demanding a token, or the dashboard stops loading.
     */
    #[Test]
    public function reads_are_not_affected_by_the_write_protection(): void
    {
        $this->loginAsAdmin();

        $this->withSession([])->getJson('/api/threat-detection/stats')->assertStatus(200);
        $this->withSession([])->getJson('/api/threat-detection/threats')->assertStatus(200);
        $this->withSession([])->getJson('/api/threat-detection/exclusion-rules')->assertStatus(200);
    }
}
