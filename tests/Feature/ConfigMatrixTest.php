<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The settings that decide whether a detection is kept, driven against one
 * fixed payload set so the differences between them are the only variable.
 *
 * Several of these had no coverage at all before this file. content_paths was
 * asserted only as far as the request attribute being set — nothing proved a
 * medium-severity match was actually suppressed, and the suppression branch in
 * the service was never executed. min_confidence was set to 0 in every test in
 * the suite. relaxed mode had never run. enabled_environments was exercised
 * only through the doctor command's warning, never through the middleware gate
 * it describes.
 */
class ConfigMatrixTest extends TestCase
{
    private const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

    /** High severity, one pattern, unambiguous. */
    private const SQLI = "' UNION SELECT password FROM users--";

    /** Medium severity. */
    private const TRAVERSAL = '../../etc/passwd';

    /** Low severity. */
    private const BLADE = '{{ 1 }}';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.only_paths' => [],
            'threat-detection.skip_paths' => [],
            'threat-detection.content_paths' => [],
            'threat-detection.safe_fields' => [],
            'threat-detection.safe_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            foreach (['scan', 'admin/posts', 'admin/users', 'public/page', 'blog/edit', 'api/v1/items'] as $uri) {
                Route::get('/' . $uri, fn () => response('OK', 200));
                Route::post('/' . $uri, fn () => response('OK', 200));
            }
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function browser(): array
    {
        return ['HTTP_USER_AGENT' => self::BROWSER];
    }

    private function logCount(): int
    {
        return DB::table('threat_logs')->count();
    }

    /** @return string[] */
    private function labels(): array
    {
        $out = DB::table('threat_logs')
            ->pluck('type')
            ->map(fn ($t) => preg_replace('/^\[[a-z-]+\] /', '', $t))
            ->all();
        sort($out);

        return array_values(array_unique($out));
    }

    private function reset(): void
    {
        DB::table('threat_logs')->delete();
        Cache::flush();
    }

    // ── only_paths vs skip_paths ────────────────────────────────────────────

    /**
     * The full truth table. only_paths is a whitelist evaluated first;
     * skip_paths is a blacklist evaluated after it. So skip_paths wins when
     * both match — a path can be inside the scanned set and still be skipped,
     * but never the reverse.
     *
     * @return array<string, array{0: array<int, string>, 1: array<int, string>, 2: bool}>
     */
    public static function pathPrecedence(): array
    {
        return [
            'neither configured' => [[], [], true],
            'only_paths matches' => [['scan'], [], true],
            'only_paths does not match' => [['admin/*'], [], false],
            'only_paths wildcard matches' => [['sc*'], [], true],
            'skip_paths matches' => [[], ['scan'], false],
            'skip_paths does not match' => [[], ['admin/*'], true],
            'both match — skip wins' => [['scan'], ['scan'], false],
            'both match by wildcard — skip wins' => [['sc*'], ['*can'], false],
            'only_paths matches, skip does not' => [['scan'], ['admin/*'], true],
            'only_paths does not match, skip does' => [['admin/*'], ['scan'], false],
            'neither matches' => [['admin/*'], ['blog/*'], false],
        ];
    }

    #[Test]
    #[DataProvider('pathPrecedence')]
    public function only_paths_and_skip_paths_resolve_with_skip_taking_precedence(
        array $onlyPaths,
        array $skipPaths,
        bool $expectScanned
    ): void {
        config([
            'threat-detection.only_paths' => $onlyPaths,
            'threat-detection.skip_paths' => $skipPaths,
        ]);

        $this->get('/scan?q=' . urlencode(self::SQLI), $this->browser())->assertStatus(200);

        $expectScanned
            ? $this->assertGreaterThan(0, $this->logCount(), 'the path should have been scanned')
            : $this->assertSame(0, $this->logCount(), 'the path should have been skipped');
    }

    #[Test]
    public function a_skipped_path_does_not_even_count_toward_the_ddos_window(): void
    {
        config(['threat-detection.skip_paths' => ['scan']]);

        foreach (range(1, 5) as $ignored) {
            $this->get('/scan', $this->browser());
        }

        $this->assertSame(
            0,
            app('threat-detection')->ddosRequestCount('127.0.0.1'),
            'skipped requests must not be counted, or skip_paths would still meter traffic'
        );
    }

    // ── safe_fields ─────────────────────────────────────────────────────────

    #[Test]
    public function safe_fields_exempts_a_query_string_parameter(): void
    {
        config(['threat-detection.safe_fields' => ['q']]);

        $this->get('/scan?q=' . urlencode(self::SQLI), $this->browser());

        $this->assertSame(0, $this->logCount());
    }

    #[Test]
    public function safe_fields_exempts_a_form_body_field(): void
    {
        config(['threat-detection.safe_fields' => ['q']]);

        $this->post('/scan', ['q' => self::SQLI], $this->browser());

        $this->assertSame(0, $this->logCount());
    }

    /**
     * The JSON body path. buildPayloadSegments() reads a JSON request through
     * $request->json() rather than $request->post(), which is a separate
     * branch — and safe_fields was only ever tested against the query string
     * and the form bag.
     */
    #[Test]
    public function safe_fields_exempts_a_json_body_field(): void
    {
        config(['threat-detection.safe_fields' => ['q']]);

        $this->postJson('/scan', ['q' => self::SQLI]);

        $this->assertSame(0, $this->logCount());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function requestShapes(): array
    {
        return ['query string' => ['query'], 'form body' => ['form'], 'json body' => ['json']];
    }

    #[Test]
    #[DataProvider('requestShapes')]
    public function safe_fields_still_scans_a_sibling_field_on_the_same_request(string $shape): void
    {
        config(['threat-detection.safe_fields' => ['exempt']]);

        $payload = ['exempt' => self::SQLI, 'other' => '<script>alert(1)</script>'];

        match ($shape) {
            'query' => $this->get('/scan?' . http_build_query($payload), $this->browser()),
            'form' => $this->post('/scan', $payload, $this->browser()),
            'json' => $this->postJson('/scan', $payload),
        };

        $this->assertContains('XSS Script Tag', $this->labels(), 'the sibling field was not scanned');
        $this->assertNotContains('SQL Injection UNION', $this->labels(), 'the exempt field was scanned');
    }

    /**
     * safe_fields matches a top-level key only. A nested key of the same name
     * is not exempt — that is what safe_paths is for, and the distinction is
     * worth pinning because it is the one an operator gets wrong.
     */
    #[Test]
    public function safe_fields_does_not_reach_into_a_nested_key_of_the_same_name(): void
    {
        config(['threat-detection.safe_fields' => ['q']]);

        $this->postJson('/scan', ['post' => ['q' => self::SQLI]]);

        $this->assertContains('SQL Injection UNION', $this->labels());
    }

    #[Test]
    public function safe_paths_reaches_the_nested_key_that_safe_fields_cannot(): void
    {
        config(['threat-detection.safe_paths' => ['post.q']]);

        $this->postJson('/scan', ['post' => ['q' => self::SQLI]]);

        $this->assertSame(0, $this->logCount());
    }

    #[Test]
    public function an_empty_safe_fields_list_scans_everything(): void
    {
        config(['threat-detection.safe_fields' => []]);

        $this->post('/scan', ['q' => self::SQLI], $this->browser());

        $this->assertContains('SQL Injection UNION', $this->labels());
    }

    // ── content_paths ───────────────────────────────────────────────────────

    /**
     * The suppression itself, not just the request attribute. The branch in
     * detectAndLogFromRequest() that drops a non-high match on a content path
     * had never been executed by any test.
     */
    #[Test]
    public function content_paths_suppress_a_medium_severity_match(): void
    {
        config(['threat-detection.content_paths' => ['admin/posts']]);

        $this->post('/admin/posts', ['body' => self::TRAVERSAL], $this->browser());

        $this->assertNotContains('Directory Traversal', $this->labels());
    }

    #[Test]
    public function content_paths_suppress_a_low_severity_match(): void
    {
        config(['threat-detection.content_paths' => ['admin/posts']]);

        $this->post('/admin/posts', ['body' => self::BLADE], $this->browser());

        $this->assertSame(0, $this->logCount());
    }

    #[Test]
    public function content_paths_do_not_suppress_a_high_severity_match(): void
    {
        config(['threat-detection.content_paths' => ['admin/posts']]);

        $this->post('/admin/posts', ['body' => self::SQLI], $this->browser());

        $this->assertContains('SQL Injection UNION', $this->labels());
    }

    /**
     * Mixed severities on one request: the high one survives, the medium one
     * does not. This is the assertion that proves the filter is per-detection
     * rather than per-request.
     */
    #[Test]
    public function content_paths_keep_the_high_severity_match_and_drop_the_medium_one_on_the_same_request(): void
    {
        config(['threat-detection.content_paths' => ['admin/posts']]);

        $this->post('/admin/posts', [
            'a' => self::SQLI,
            'b' => self::TRAVERSAL,
        ], $this->browser());

        $labels = $this->labels();
        $this->assertContains('SQL Injection UNION', $labels);
        $this->assertNotContains('Directory Traversal', $labels);
    }

    #[Test]
    public function content_paths_only_apply_to_the_paths_they_name(): void
    {
        config(['threat-detection.content_paths' => ['admin/posts']]);

        $this->post('/blog/edit', ['body' => self::TRAVERSAL], $this->browser());

        $this->assertContains('Directory Traversal', $this->labels());
    }

    #[Test]
    public function content_paths_support_wildcards(): void
    {
        config(['threat-detection.content_paths' => ['admin/*']]);

        $this->post('/admin/posts', ['body' => self::TRAVERSAL], $this->browser());

        $this->assertNotContains('Directory Traversal', $this->labels());
    }

    // ── min_confidence ──────────────────────────────────────────────────────

    /**
     * min_confidence drops a detection after it has been made, without a trace
     * anywhere. Nothing in the suite had ever set it above 0, so the discard
     * had never happened.
     */
    #[Test]
    public function min_confidence_above_the_score_drops_the_detection_silently(): void
    {
        config(['threat-detection.min_confidence' => 100]);

        $this->post('/scan', ['q' => self::SQLI], $this->browser())->assertStatus(200);

        $this->assertSame(0, $this->logCount());
    }

    #[Test]
    public function min_confidence_below_the_score_keeps_the_detection(): void
    {
        config(['threat-detection.min_confidence' => 10]);

        $this->post('/scan', ['q' => self::SQLI], $this->browser());

        $this->assertContains('SQL Injection UNION', $this->labels());
    }

    /**
     * The boundary. The same request is scored once; raising the threshold one
     * point past that score must be the point at which it disappears.
     */
    #[Test]
    public function min_confidence_is_an_inclusive_floor_at_exactly_the_score(): void
    {
        config(['threat-detection.min_confidence' => 0]);
        $this->post('/scan', ['q' => self::SQLI], $this->browser());

        $score = (int) DB::table('threat_logs')->value('confidence_score');
        $this->assertGreaterThan(0, $score);

        $this->reset();
        config(['threat-detection.min_confidence' => $score]);
        $this->post('/scan', ['q' => self::SQLI], $this->browser());
        $this->assertGreaterThan(0, $this->logCount(), 'a score exactly at the threshold must be kept');

        $this->reset();
        config(['threat-detection.min_confidence' => $score + 1]);
        $this->post('/scan', ['q' => self::SQLI], $this->browser());
        $this->assertSame(0, $this->logCount(), 'a score one below the threshold must be dropped');
    }

    /**
     * min_confidence is combined with the mode's own floor via max(), so it can
     * only ever tighten detection. Setting it to 0 does not undo what the mode
     * is doing — and in relaxed mode most of the work is done by the severity
     * filter rather than by the confidence floor, which min_confidence cannot
     * reach at all.
     */
    #[Test]
    public function a_min_confidence_of_zero_does_not_undo_the_relaxed_mode_severity_filter(): void
    {
        config([
            'threat-detection.detection_mode' => 'relaxed',
            'threat-detection.min_confidence' => 0,
        ]);

        $this->post('/scan', ['q' => self::BLADE], $this->browser());
        $this->assertSame(0, $this->logCount(), 'relaxed mode logged a low-severity match');

        // The same payload under strict, to show it is the mode doing this and
        // not the payload simply going undetected.
        $this->reset();
        config(['threat-detection.detection_mode' => 'strict']);

        $this->post('/scan', ['q' => self::BLADE], $this->browser());
        $this->assertGreaterThan(0, $this->logCount());
    }

    /**
     * The other direction: a min_confidence above the mode floor does bind.
     */
    #[Test]
    public function min_confidence_tightens_a_mode_whose_own_floor_is_lower(): void
    {
        config([
            'threat-detection.detection_mode' => 'strict', // floor 0
            'threat-detection.min_confidence' => 100,
        ]);

        $this->post('/scan', ['q' => self::SQLI], $this->browser());

        $this->assertSame(0, $this->logCount());
    }

    // ── detection modes against one payload set ────────────────────────────

    /**
     * @return array<string, array{0: string}>
     */
    public static function mixedSeverityPayloads(): array
    {
        return [
            'high severity sql injection' => [self::SQLI],
            'medium severity traversal' => [self::TRAVERSAL],
            'low severity blade syntax' => [self::BLADE],
        ];
    }

    /**
     * The containment property: whatever relaxed reports, balanced reports
     * too, and whatever balanced reports, strict reports too. This is what
     * "sensitivity" has to mean for the three modes to be comparable at all.
     */
    #[Test]
    #[DataProvider('mixedSeverityPayloads')]
    public function each_mode_reports_a_superset_of_the_looser_mode_for_the_same_payload(string $payload): void
    {
        $seen = [];

        foreach (['relaxed', 'balanced', 'strict'] as $mode) {
            $this->reset();
            config(['threat-detection.detection_mode' => $mode]);
            $this->get('/scan?q=' . urlencode($payload), $this->browser());
            $seen[$mode] = $this->labels();
        }

        foreach ($seen['relaxed'] as $label) {
            $this->assertContains($label, $seen['balanced'], "balanced lost '{$label}' that relaxed reported");
        }
        foreach ($seen['balanced'] as $label) {
            $this->assertContains($label, $seen['strict'], "strict lost '{$label}' that balanced reported");
        }
    }

    #[Test]
    public function relaxed_mode_never_reports_a_non_high_severity_match(): void
    {
        config(['threat-detection.detection_mode' => 'relaxed']);

        // Enough simultaneous matches to clear relaxed's confidence floor.
        $this->get('/scan?a=' . urlencode(self::SQLI) . '&b=' . urlencode('<script>alert(1)</script>') . '&c=' . urlencode(self::TRAVERSAL), $this->browser());

        $levels = DB::table('threat_logs')->distinct()->pluck('threat_level')->all();

        $this->assertGreaterThan(0, count($levels), 'relaxed mode logged nothing at all for three simultaneous attacks');
        $this->assertSame(['high'], $levels);
    }

    #[Test]
    public function strict_mode_reports_low_severity_matches_that_balanced_may_drop(): void
    {
        config(['threat-detection.detection_mode' => 'strict']);
        $this->get('/scan?q=' . urlencode(self::BLADE), $this->browser());

        $this->assertGreaterThan(0, $this->logCount());
    }

    // ── whitelisted IPs ─────────────────────────────────────────────────────

    /**
     * @return array<string, array{0: array<int, string>, 1: string, 2: bool}>
     */
    public static function whitelistCases(): array
    {
        return [
            'exact match' => [['203.0.113.7'], '203.0.113.7', true],
            'exact non-match' => [['203.0.113.7'], '203.0.113.8', false],
            '/24 inside' => [['203.0.113.0/24'], '203.0.113.200', true],
            '/24 outside' => [['203.0.113.0/24'], '203.0.114.1', false],
            '/16 inside' => [['10.0.0.0/16'], '10.0.255.254', true],
            '/16 outside' => [['10.0.0.0/16'], '10.1.0.1', false],
            '/32 as an exact address' => [['198.51.100.5/32'], '198.51.100.5', true],
            '/32 neighbour' => [['198.51.100.5/32'], '198.51.100.6', false],
            'several entries, second matches' => [['203.0.113.7', '10.0.0.0/8'], '10.20.30.40', true],
            'untrimmed entry from a stale published config' => [[' 203.0.113.7 '], '203.0.113.7', true],
            'empty list' => [[], '203.0.113.7', false],
            'entry that is not an address' => [['not-an-ip'], '203.0.113.7', false],
        ];
    }

    #[Test]
    #[DataProvider('whitelistCases')]
    public function a_whitelisted_client_is_exempt_from_detection_entirely(array $list, string $ip, bool $whitelisted): void
    {
        config(['threat-detection.whitelisted_ips' => $list]);

        $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->get('/scan?q=' . urlencode(self::SQLI), $this->browser())
            ->assertStatus(200);

        $whitelisted
            ? $this->assertSame(0, $this->logCount(), "{$ip} should have been exempt")
            : $this->assertGreaterThan(0, $this->logCount(), "{$ip} should have been scanned");
    }

    // ── enabled and enabled_environments ────────────────────────────────────

    #[Test]
    public function detection_is_off_when_enabled_is_false(): void
    {
        config(['threat-detection.enabled' => false]);

        $this->get('/scan?q=' . urlencode(self::SQLI), $this->browser())->assertStatus(200);

        $this->assertSame(0, $this->logCount());
    }

    /**
     * The environment gate, driven through the middleware rather than through
     * the doctor command's warning about it. The application environment here
     * is 'testing', which is exactly the case the shipped default excludes —
     * enabled_environments ships as ['production', 'staging', 'local'].
     */
    #[Test]
    public function detection_is_off_when_the_current_environment_is_not_listed(): void
    {
        $this->assertSame('testing', $this->app->environment());

        config(['threat-detection.enabled_environments' => ['production', 'staging', 'local']]);

        $this->get('/scan?q=' . urlencode(self::SQLI), $this->browser())->assertStatus(200);

        $this->assertSame(0, $this->logCount());
    }

    #[Test]
    public function detection_is_on_when_the_current_environment_is_listed(): void
    {
        config(['threat-detection.enabled_environments' => ['testing']]);

        $this->get('/scan?q=' . urlencode(self::SQLI), $this->browser());

        $this->assertGreaterThan(0, $this->logCount());
    }

    /**
     * An empty or null list means "every environment" rather than "none" — the
     * gate is skipped entirely when the value is falsy. Worth pinning: the
     * opposite reading would silently disable the package.
     */
    #[Test]
    public function an_empty_environment_list_means_every_environment(): void
    {
        foreach ([null, []] as $value) {
            $this->reset();
            config(['threat-detection.enabled_environments' => $value]);

            $this->get('/scan?q=' . urlencode(self::SQLI), $this->browser());

            $this->assertGreaterThan(0, $this->logCount(), 'a falsy environment list must not disable detection');
        }
    }

    // ── api_route_filtering ─────────────────────────────────────────────────

    #[Test]
    public function api_route_filtering_suppresses_the_levels_it_names_on_api_paths(): void
    {
        config([
            'threat-detection.api_route_filtering.enabled' => true,
            'threat-detection.api_route_filtering.suppress_levels' => ['low', 'medium'],
        ]);

        $this->postJson('/api/v1/items', ['a' => self::SQLI, 'b' => self::TRAVERSAL]);

        $labels = $this->labels();
        $this->assertContains('SQL Injection UNION', $labels);
        $this->assertNotContains('Directory Traversal', $labels);
    }

    #[Test]
    public function api_route_filtering_leaves_non_api_paths_alone(): void
    {
        config([
            'threat-detection.api_route_filtering.enabled' => true,
            'threat-detection.api_route_filtering.suppress_levels' => ['low', 'medium'],
        ]);

        $this->post('/scan', ['b' => self::TRAVERSAL], $this->browser());

        $this->assertContains('Directory Traversal', $this->labels());
    }

    // ── max_detections_per_request ─────────────────────────────────────────

    #[Test]
    public function max_detections_per_request_caps_how_many_patterns_are_recorded(): void
    {
        config(['threat-detection.max_detections_per_request' => 2]);

        $this->post('/scan', [
            'a' => self::SQLI,
            'b' => '<script>alert(1)</script>',
            'c' => self::TRAVERSAL,
            'd' => 'system("id")',
            'e' => '${jndi:ldap://x/a}',
        ], $this->browser());

        $this->assertLessThanOrEqual(2, $this->logCount());
    }

    #[Test]
    public function a_max_detections_of_zero_means_unlimited(): void
    {
        config(['threat-detection.max_detections_per_request' => 0]);

        $this->post('/scan', [
            'a' => self::SQLI,
            'b' => '<script>alert(1)</script>',
            'c' => self::TRAVERSAL,
            'd' => 'system("id")',
        ], $this->browser());

        $this->assertGreaterThan(2, $this->logCount());
    }

    // ── table_name ──────────────────────────────────────────────────────────

    /**
     * A non-default table name is offered in config and never used by any
     * test, so nothing proved the writes and the reads agree about it.
     */
    #[Test]
    public function a_non_default_table_name_is_used_for_the_write(): void
    {
        config(['threat-detection.table_name' => 'security_events']);
        $this->createThreatLogsTable();

        $this->post('/scan', ['q' => self::SQLI], $this->browser())->assertStatus(200);

        $this->assertGreaterThan(0, DB::table('security_events')->count());
        $this->assertSame(0, DB::table('threat_logs')->count());
    }
}
