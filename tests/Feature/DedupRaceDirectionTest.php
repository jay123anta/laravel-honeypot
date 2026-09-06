<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD_AUDIT.md "Not verified" item 7: cross-request dedup is a check-then-act.
 *
 *     isRecentlyLogged()  ->  Cache::has(...)
 *     markAsLogged()      ->  Cache::put(...)
 *
 * Two requests can both read `false` before either writes. No parallel-request
 * testing was done for the audit and none is done here — PHPUnit is one
 * process and a green single-threaded test would say nothing about a real
 * race.
 *
 * What *can* be established without parallelism is the direction the race
 * fails in, which is the part that decides whether it is a security problem:
 *
 *   - the cache mark is only ever consulted to SKIP a write;
 *   - it is only ever set AFTER a successful write;
 *   - therefore a lost race produces a duplicate row, never a missing one.
 *
 * A detector that occasionally logs an attack twice under load is noisy. One
 * that occasionally logs it zero times is broken. These tests pin which of
 * those the race can produce, by driving the extreme case: a cache that never
 * remembers anything, which is the same state every racing request observes.
 */
class DedupRaceDirectionTest extends TestCase
{
    private const SQLI = "' UNION SELECT password FROM users--";

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.skip_paths' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->post('/race', fn () => response('OK', 200));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function attack(): void
    {
        $this->post('/race', ['q' => self::SQLI])->assertStatus(200);
    }

    private function rowCount(): int
    {
        return DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->count();
    }

    /**
     * The control: dedup works at all. Without this, "three requests produced
     * three rows" below would be indistinguishable from dedup never running.
     */
    #[Test]
    public function repeated_identical_attacks_normally_collapse_to_one_row(): void
    {
        $this->attack();
        $this->attack();
        $this->attack();

        $this->assertSame(1, $this->rowCount());
    }

    /**
     * And that the mark is what does it — not something else in the pipeline.
     */
    #[Test]
    public function clearing_the_mark_lets_the_next_identical_attack_log_again(): void
    {
        $this->attack();
        $this->assertSame(1, $this->rowCount());

        Cache::flush();
        $this->attack();

        $this->assertSame(2, $this->rowCount());
    }

    /**
     * The race, driven to its limit. Every request sees `has() === false`,
     * which is exactly what both sides of a lost race see. The result is more
     * rows, never fewer — the attack is still recorded every single time.
     */
    #[Test]
    public function a_cache_that_never_remembers_over_logs_rather_than_losing_a_detection(): void
    {
        config(['cache.default' => 'null']);

        $this->attack();
        $this->attack();
        $this->attack();

        $this->assertSame(
            3,
            $this->rowCount(),
            'a detection was lost when the dedup mark did not persist, so the race can suppress an attack'
        );
    }

    /**
     * The same property stated the other way: there is no cache state in which
     * a first-ever attack from an address goes unlogged. If the mark could be
     * present before the write, a racing request could skip a row that was
     * never actually written.
     */
    #[Test]
    public function the_mark_is_absent_until_a_row_has_actually_been_written(): void
    {
        $ip = '127.0.0.1';
        $key = "threat_logged:{$ip}:[middleware] SQL Injection UNION";

        $this->assertFalse(Cache::has($key), 'the dedup mark exists before anything was logged');

        $this->attack();

        $this->assertTrue(Cache::has($key), 'nothing marked the threat as logged, so dedup never engages');
        $this->assertSame(1, $this->rowCount());
    }

    /**
     * The DDoS counter, by contrast, is built on Cache::add — which is atomic
     * where the store supports it. Pinned because it is the one counter in the
     * package where a lost race would matter in the unsafe direction: a reset
     * window means a flood is never reported.
     */
    #[Test]
    public function a_second_window_start_never_resets_a_running_ddos_counter(): void
    {
        $key = 'ddos_window_probe';

        $this->assertTrue(Cache::add($key, 0, now()->addSeconds(60)));
        Cache::increment($key);
        Cache::increment($key);

        // What a racing request would do on arrival.
        $this->assertFalse(Cache::add($key, 0, now()->addSeconds(60)), 'add() overwrote a live counter');
        $this->assertSame(2, (int) Cache::get($key), 'the counter was reset, so a flood would go unreported');
    }
}
