<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Phase 6 — can an attacker make the detector stop reporting them?
 *
 * Three mechanisms exist that deliberately drop detections: the five-minute
 * dedup cache, max_detections_per_request, and the confidence floor. Each is
 * reasonable in isolation. The question is whether an attacker can trigger one
 * on purpose, cheaply, to cover an attack that follows.
 *
 * Plus the user-agent short-circuit, which decides how much of the scanner
 * list a request is compared against.
 */
class DetectionSuppressionTest extends TestCase
{
    private const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

    private const SQLI = "' UNION SELECT password FROM users--";

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'balanced',
            'threat-detection.min_confidence' => 0,
            'threat-detection.max_detections_per_request' => 0,
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.notifications.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/s', fn () => response('OK', 200));
            Route::post('/s', fn () => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function types(): array
    {
        return DB::table('threat_logs')->pluck('type')->all();
    }

    // ── the user-agent short-circuit ───────────────────────────────────────

    /**
     * TD-009 — a scanner that sends a browser-shaped user agent is not
     * identified as a scanner.
     *
     * detectSuspiciousUserAgent() (ThreatDetectionService.php:1600) short-
     * circuits when the UA contains both "mozilla/" and "gecko": it then
     * checks five headless markers and ten "spoof check" names, and returns.
     * The full list it skips holds roughly fifty scanners and bots.
     *
     * So "Mozilla/5.0 (X11; Linux) Gecko/20100101 sqlmap/1.7.2" is not
     * reported as SQLMap, while the bare "sqlmap/1.7.2" is. The spoof list
     * exists precisely to catch UAs that embed Mozilla — it just contains ten
     * AI-crawler names rather than the scanner list.
     *
     * Pattern detection is unaffected, and ConfidenceScorer::
     * isAttackToolUserAgent() reads the raw UA, so the +25 confidence bonus
     * still applies. What is lost is the "[user-agent] SQLMap Scanner" row —
     * the one an operator greps for.
     *
     * @return array<string, array{0: string}>
     */
    public static function scannerNames(): array
    {
        return [
            'sqlmap' => ['sqlmap/1.7.2'],
            'nikto' => ['Nikto/2.5.0'],
            'nmap' => ['Nmap Scripting Engine'],
            'acunetix' => ['acunetix-wvs'],
            'nessus' => ['Nessus/10.5'],
            'nuclei' => ['Nuclei - Open-source project'],
            'metasploit' => ['Metasploit RSpec'],
            'wpscan' => ['WPScan v3.8'],
            'ffuf' => ['Fuzz Faster U Fool ffuf/2.0'],
            'masscan' => ['masscan/1.3'],
        ];
    }

    #[Test]
    #[DataProvider('scannerNames')]
    public function a_scanner_is_still_identified_when_it_hides_behind_a_browser_user_agent(string $scanner): void
    {
        $bare = 'Tool/1.0 ' . $scanner;
        $spoofed = 'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0 ' . $scanner;

        $this->get('/s', ['User-Agent' => $bare])->assertStatus(200);
        $detectedBare = array_filter($this->types(), fn ($t) => str_contains($t, '[user-agent]'));

        $this->assertNotEmpty($detectedBare, "the bare user agent '{$bare}' was not detected at all");

        DB::table('threat_logs')->delete();
        Cache::flush();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.50'])
            ->get('/s', ['User-Agent' => $spoofed])->assertStatus(200);
        $detectedSpoofed = array_filter($this->types(), fn ($t) => str_contains($t, '[user-agent]'));

        $this->assertNotEmpty(
            $detectedSpoofed,
            "'{$scanner}' is reported on its own but not when the user agent also claims to be a browser"
        );
    }

    /**
     * The half that does work, asserted so the finding above is not read as
     * "user-agent detection is broken". Headless markers and the ten listed
     * AI crawlers are caught through the short-circuit.
     */
    #[Test]
    public function the_short_circuit_still_catches_headless_browsers_and_the_listed_crawlers(): void
    {
        foreach (['HeadlessChrome/120.0', 'GPTBot/1.0', 'ClaudeBot/1.0'] as $marker) {
            DB::table('threat_logs')->delete();
            Cache::flush();

            $this->get('/s', ['User-Agent' => 'Mozilla/5.0 (X11; Linux) Gecko/20100101 ' . $marker]);

            $this->assertNotEmpty(
                array_filter($this->types(), fn ($t) => str_contains($t, '[user-agent]')),
                "{$marker} was not detected behind a browser user agent"
            );
        }
    }

    /**
     * The confidence bonus is computed from the raw user agent by a different
     * code path, so it survives the short-circuit. Worth pinning: it is the
     * only thing that still distinguishes a spoofed scanner from a browser.
     */
    #[Test]
    public function the_attack_tool_confidence_bonus_survives_a_spoofed_browser_user_agent(): void
    {
        $this->get('/s?q=' . urlencode(self::SQLI), ['User-Agent' => self::BROWSER])->assertStatus(200);
        $browserScore = (int) DB::table('threat_logs')->value('confidence_score');

        DB::table('threat_logs')->delete();
        Cache::flush();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.51'])
            ->get('/s?q=' . urlencode(self::SQLI), ['User-Agent' => self::BROWSER . ' sqlmap/1.7.2'])
            ->assertStatus(200);
        $spoofedScore = (int) DB::table('threat_logs')->value('confidence_score');

        $this->assertGreaterThan($browserScore, $spoofedScore, 'the attack-tool bonus was lost to the short-circuit');
    }

    // ── dedup poisoning ────────────────────────────────────────────────────

    /**
     * TD-010 — the dedup cache can be primed.
     *
     * A detection is written once per (ip, type) per five minutes. The mark is
     * set by the first detection of that type, whatever produced it — so an
     * attacker can send one cheap, harmless-looking request that trips a type,
     * and then attack freely with that same type for five minutes while the
     * log records nothing further.
     *
     * This is the documented behaviour of dedup and is not a defect on its
     * own. It is recorded because of what it means operationally: the log
     * shows *that* an attack type occurred, never how many times, so volume is
     * not measurable from threat_logs and an escalation cannot be seen. The
     * README presents the row count as a threat count.
     */
    #[Test]
    public function a_first_probe_suppresses_the_logging_of_everything_that_follows_it(): void
    {
        // One request. Enough to set the mark.
        $this->get('/s?q=' . urlencode(self::SQLI), ['User-Agent' => self::BROWSER]);
        $afterFirst = DB::table('threat_logs')->count();

        // Fifty more, from the same address, in the same window.
        for ($i = 0; $i < 50; $i++) {
            $this->get('/s?q=' . urlencode(self::SQLI . " -- {$i}"), ['User-Agent' => self::BROWSER]);
        }

        $this->assertGreaterThan(0, $afterFirst);
        $this->assertSame(
            $afterFirst,
            DB::table('threat_logs')->count(),
            'the follow-up requests were logged, so dedup is not suppressing them'
        );
    }

    /**
     * The consequence, stated as the question an operator actually asks. It
     * cannot be answered from the table.
     */
    #[Test]
    public function the_log_records_how_many_times_an_attack_type_was_attempted(): void
    {
        for ($i = 0; $i < 25; $i++) {
            $this->get('/s?q=' . urlencode(self::SQLI), ['User-Agent' => self::BROWSER]);
        }

        $this->assertSame(
            25,
            DB::table('threat_logs')->where('type', '[middleware] SQL Injection UNION')->count(),
            'attempt volume is not recoverable from threat_logs'
        );
    }

    // ── max_detections abuse ───────────────────────────────────────────────

    /**
     * TD-011 — max_detections_per_request can be filled with noise.
     *
     * The cap stops scanning after N matches. Patterns are evaluated in a
     * fixed order, so an attacker who includes enough cheap matches that sit
     * earlier in that order consumes the budget before the real payload is
     * reached.
     *
     * Only applies when an operator has set the cap — it ships as 0, meaning
     * unlimited — which is why this is medium rather than high. The config
     * comment recommends it as a performance measure with no mention of the
     * trade.
     */
    #[Test]
    public function a_capped_request_still_reports_the_most_severe_match_rather_than_the_first_few(): void
    {
        config(['threat-detection.max_detections_per_request' => 3]);

        // Three *low*-severity matches, then the payload that matters. The
        // padding has to be low severity for this to be a question about
        // ordering at all — when everything competing is high, the cap simply
        // keeps the first ones and nothing can do better. That case is pinned
        // separately below.
        $this->post('/s', [
            'a' => '{{ 1 }}',
            'b' => '${price}',
            'c' => 'trace_id',
            'd' => self::SQLI,
        ], ['User-Agent' => self::BROWSER])->assertStatus(200);

        $this->assertContains(
            '[middleware] SQL Injection UNION',
            $this->types(),
            'the cap was filled by lower-severity matches and the injection went unrecorded: ' . implode(', ', $this->types())
        );
    }

    /** The cap is still a cap: it bounds what is reported. */
    #[Test]
    public function the_cap_still_limits_how_many_detections_are_recorded(): void
    {
        config(['threat-detection.max_detections_per_request' => 3]);

        $this->post('/s', [
            'a' => '{{ 1 }}',
            'b' => '${price}',
            'c' => 'trace_id',
            'd' => self::SQLI,
            'e' => '<script>alert(1)</script>',
        ], ['User-Agent' => self::BROWSER])->assertStatus(200);

        $this->assertLessThanOrEqual(3, DB::table('threat_logs')->count());
    }

    /**
     * When every competing match is the same severity the cap keeps the first
     * ones found, which is all it can do. Pinned so the fix is not mistaken
     * for a guarantee that the "most interesting" match always survives.
     */
    #[Test]
    public function a_cap_full_of_equally_severe_matches_keeps_the_ones_found_first(): void
    {
        config(['threat-detection.max_detections_per_request' => 2]);

        $this->post('/s', [
            'a' => '<script>alert(1)</script>',
            'b' => self::SQLI,
        ], ['User-Agent' => self::BROWSER])->assertStatus(200);

        $levels = DB::table('threat_logs')->distinct()->pluck('threat_level')->all();

        $this->assertSame(['high'], $levels);
        $this->assertLessThanOrEqual(2, DB::table('threat_logs')->count());
    }

    // ── the exclusion rules an attacker would like to create ───────────────

    /**
     * Exclusion rules are the strongest suppression in the package: a rule
     * silences a label on a path for everyone, permanently. Creating one is a
     * write, and writes are behind write_guard — asserted here from the
     * detection side rather than the HTTP side, so a change to either is
     * caught.
     */
    #[Test]
    public function an_exclusion_rule_suppresses_a_real_attack_which_is_why_creating_one_is_privileged(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => 'SQL Injection UNION',
            'path_pattern' => 's',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->get('/s?q=' . urlencode(self::SQLI), ['User-Agent' => self::BROWSER])->assertStatus(200);

        $this->assertNotContains('[middleware] SQL Injection UNION', $this->types());
    }
}
