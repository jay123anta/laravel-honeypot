<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Events\DdosThresholdExceeded;
use JayAnta\ThreatDetection\Jobs\StoreThreatLog;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The machinery around detection: deduplication, the DDoS counter, and the
 * queue.
 *
 * The queue half is the gap this file was written for. StoreThreatLog was the
 * least covered class in the package at 5.9% of lines — one existing test
 * asserted the job was *dispatched* and nothing ever executed its body, so the
 * insert it performs, the notification it sends and the rethrow that drives
 * its retries had never run. An operator who enables the queue is running code
 * no test has touched.
 */
class DedupAndQueueTest extends TestCase
{
    private const SQLI = "' UNION SELECT password FROM users--";

    private const XSS = '<script>alert(1)</script>';

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

        Route::middleware('threat-detect')->group(function () {
            Route::get('/infra', fn () => response('OK', 200));
            Route::post('/infra', fn () => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        config(['cache.default' => 'array']);
        Cache::flush();
        parent::tearDown();
    }

    private function rowsOfType(string $type): int
    {
        return DB::table('threat_logs')->where('type', $type)->count();
    }

    // ── deduplication ───────────────────────────────────────────────────────

    #[Test]
    public function the_same_threat_type_from_the_same_ip_is_logged_once_inside_the_window(): void
    {
        foreach (range(1, 5) as $ignored) {
            $this->get('/infra?q=' . urlencode(self::SQLI));
        }

        $this->assertSame(1, $this->rowsOfType('[middleware] SQL Injection UNION'));
    }

    #[Test]
    public function a_different_threat_type_from_the_same_ip_is_logged_separately_inside_the_window(): void
    {
        $this->get('/infra?q=' . urlencode(self::SQLI));
        $this->get('/infra?q=' . urlencode(self::XSS));

        $this->assertSame(1, $this->rowsOfType('[middleware] SQL Injection UNION'));
        $this->assertSame(1, $this->rowsOfType('[middleware] XSS Script Tag'));
    }

    #[Test]
    public function the_same_threat_type_from_a_different_ip_is_logged_separately(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.1'])->get('/infra?q=' . urlencode(self::SQLI));
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.2'])->get('/infra?q=' . urlencode(self::SQLI));

        $this->assertSame(2, $this->rowsOfType('[middleware] SQL Injection UNION'));
    }

    /**
     * The window is five minutes. After it lapses the same attacker tripping
     * the same pattern is a new event and must be recorded again — otherwise a
     * sustained campaign would appear in the log as a single hit.
     */
    #[Test]
    public function the_same_threat_type_is_logged_again_once_the_window_has_lapsed(): void
    {
        $this->get('/infra?q=' . urlencode(self::SQLI));
        $this->assertSame(1, $this->rowsOfType('[middleware] SQL Injection UNION'));

        $this->travel(6)->minutes();

        $this->get('/infra?q=' . urlencode(self::SQLI));
        $this->assertSame(2, $this->rowsOfType('[middleware] SQL Injection UNION'));

        $this->travelBack();
    }

    #[Test]
    public function a_repeat_just_inside_the_window_is_still_deduplicated(): void
    {
        $this->get('/infra?q=' . urlencode(self::SQLI));

        $this->travel(4)->minutes();

        $this->get('/infra?q=' . urlencode(self::SQLI));
        $this->assertSame(1, $this->rowsOfType('[middleware] SQL Injection UNION'));

        $this->travelBack();
    }

    /**
     * Two matches of the same type in one request are one detection, not two.
     * That is a separate mechanism from the cross-request cache mark — a
     * within-request set — and it has its own failure mode: duplicate rows
     * from a single insert.
     */
    #[Test]
    public function one_request_matching_the_same_pattern_twice_produces_a_single_row(): void
    {
        $this->post('/infra', ['a' => self::SQLI, 'b' => self::SQLI]);

        $this->assertSame(1, $this->rowsOfType('[middleware] SQL Injection UNION'));
    }

    /**
     * The v1.3.1 guarantee: the five-minute mark is applied only after a
     * successful write. A failed insert must not mute the threat for the rest
     * of the window, or a broken schema silences the detector twice over.
     */
    #[Test]
    public function a_failed_write_does_not_mark_the_threat_as_already_logged(): void
    {
        Schema::dropIfExists('threat_logs');

        $this->get('/infra?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->createThreatLogsTable();

        $this->get('/infra?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->assertSame(1, $this->rowsOfType('[middleware] SQL Injection UNION'), 'the retry was suppressed by a mark set on a failed write');
    }

    // ── the DDoS counter and its cache-driver requirement ──────────────────

    /**
     * @return array<string, array{0: string,1: bool}> driver, counts
     */
    public static function cacheDrivers(): array
    {
        return [
            'array is atomic enough' => ['array', true],
            'file is not' => ['file', false],
            'database is not' => ['database', false],
            'null is not' => ['null', false],
        ];
    }

    #[Test]
    #[DataProvider('cacheDrivers')]
    public function ddos_counting_runs_only_on_a_driver_that_supports_atomic_increment(string $driver, bool $counts): void
    {
        config([
            'cache.default' => $driver,
            'threat-detection.ddos.threshold' => 2,
            'threat-detection.ddos.window' => 60,
        ]);

        foreach (range(1, 5) as $ignored) {
            $this->get('/infra')->assertStatus(200);
        }

        $counts
            ? $this->assertGreaterThan(0, $this->rowsOfType('[ddos] Excessive Requests'))
            : $this->assertSame(0, $this->rowsOfType('[ddos] Excessive Requests'), "DDoS detection ran on '{$driver}'");
    }

    /**
     * BUG 7 (fixed) — flushCaches() used not to reset $ddosCacheWarned.
     *
     * ThreatDetectionService::flushCaches() is documented as dropping every
     * process-lifetime cache, and it resets the sibling warn-once flag
     * $writeFailureWarned (line 1004). It misses $ddosCacheWarned (line 1251),
     * so once the warning has been emitted in a process it can never be
     * emitted again — including after a config change that would make it
     * newly relevant, which is exactly the case flushCaches() exists for under
     * Octane.
     *
     * The consequence in production is small: an operator loses a repeat of a
     * warning they have already seen. The consequence here is that the flag
     * has to be reset by hand for the behaviour to be observable at all.
     */
    #[Test]
    public function a_non_atomic_cache_driver_is_explained_to_the_operator_once(): void
    {
        $this->resetDdosCacheWarning();

        Log::spy();
        config(['cache.default' => 'file']);

        $this->get('/infra');
        $this->get('/infra');

        Log::shouldHaveReceived('warning')
            ->withArgs(fn ($m) => str_contains($m, 'does not support atomic increment'))
            ->once();
    }

    #[Test]
    public function flush_caches_resets_every_warn_once_flag_it_claims_to(): void
    {
        $this->resetDdosCacheWarning();

        config(['cache.default' => 'file']);
        $this->get('/infra');

        ThreatDetectionService::flushCaches();

        $property = new \ReflectionProperty(
            ThreatDetectionService::class,
            'ddosCacheWarned'
        );

        $this->assertFalse($property->getValue(), 'flushCaches() left $ddosCacheWarned set');
    }

    private function resetDdosCacheWarning(): void
    {
        $property = new \ReflectionProperty(
            ThreatDetectionService::class,
            'ddosCacheWarned'
        );
        $property->setValue(null, false);
    }

    #[Test]
    public function the_ddos_helper_reports_zero_on_a_driver_where_counting_is_disabled(): void
    {
        config(['cache.default' => 'file']);

        $this->get('/infra');

        $this->assertSame(0, app('threat-detection')->ddosRequestCount('127.0.0.1'));
        $this->assertFalse(app('threat-detection')->isDdosThresholdExceeded('127.0.0.1'));
    }

    #[Test]
    public function a_flood_logs_once_per_window_rather_than_once_per_request(): void
    {
        config(['threat-detection.ddos.threshold' => 2, 'threat-detection.ddos.window' => 60]);

        foreach (range(1, 20) as $ignored) {
            $this->get('/infra');
        }

        $this->assertSame(1, $this->rowsOfType('[ddos] Excessive Requests'));
    }

    #[Test]
    public function the_ddos_event_carries_the_count_the_threshold_and_the_window(): void
    {
        Event::fake([DdosThresholdExceeded::class]);
        config(['threat-detection.ddos.threshold' => 2, 'threat-detection.ddos.window' => 90]);

        foreach (range(1, 5) as $ignored) {
            $this->get('/infra');
        }

        Event::assertDispatched(DdosThresholdExceeded::class, function ($event) {
            return $event->threshold === 2
                && $event->windowSeconds === 90
                && $event->requestCount > 2;
        });
    }

    // ── the queue path ──────────────────────────────────────────────────────

    #[Test]
    public function the_job_is_dispatched_when_the_queue_is_enabled(): void
    {
        Queue::fake();
        config(['threat-detection.queue.enabled' => true]);

        $this->get('/infra?q=' . urlencode(self::SQLI))->assertStatus(200);

        Queue::assertPushed(StoreThreatLog::class);
        $this->assertSame(0, DB::table('threat_logs')->count(), 'the row was written synchronously as well as queued');
    }

    #[Test]
    public function no_job_is_dispatched_when_the_queue_is_disabled(): void
    {
        Queue::fake();
        config(['threat-detection.queue.enabled' => false]);

        $this->get('/infra?q=' . urlencode(self::SQLI))->assertStatus(200);

        Queue::assertNothingPushed();
        $this->assertGreaterThan(0, DB::table('threat_logs')->count());
    }

    /**
     * The queued and synchronous paths must produce the same row. They build
     * the insert in different places — the service inserts directly, the job
     * inserts from its serialised payload — so a column added to one and not
     * the other would go unnoticed.
     */
    #[Test]
    public function the_queued_path_and_the_synchronous_path_write_identical_rows(): void
    {
        $columns = ['ip_address', 'url', 'user_agent', 'type', 'payload', 'threat_level', 'confidence_score', 'confidence_label', 'user_id'];

        config(['threat-detection.queue.enabled' => false]);
        $this->get('/infra?q=' . urlencode(self::SQLI));
        $synchronous = DB::table('threat_logs')->orderBy('type')->get($columns)->toArray();

        DB::table('threat_logs')->delete();
        Cache::flush();

        // queue.connection is left unset, so the job runs on the default
        // connection — 'sync' under phpunit.xml, which executes it inline.
        config(['threat-detection.queue.enabled' => true]);
        $this->get('/infra?q=' . urlencode(self::SQLI));
        $queued = DB::table('threat_logs')->orderBy('type')->get($columns)->toArray();

        $this->assertNotEmpty($synchronous);
        $this->assertEquals($synchronous, $queued, 'the queued path wrote a different row from the synchronous one');
    }

    #[Test]
    public function the_queued_job_actually_writes_every_threat_from_a_multi_match_request(): void
    {
        config(['threat-detection.queue.enabled' => true]);

        $this->post('/infra', ['a' => self::SQLI, 'b' => self::XSS, 'c' => '../../etc/passwd']);

        $this->assertGreaterThanOrEqual(3, DB::table('threat_logs')->count());
    }

    #[Test]
    public function the_job_honours_a_configured_queue_name(): void
    {
        Queue::fake();
        config([
            'threat-detection.queue.enabled' => true,
            'threat-detection.queue.queue' => 'security',
        ]);

        $this->get('/infra?q=' . urlencode(self::SQLI));

        Queue::assertPushedOn('security', StoreThreatLog::class);
    }

    #[Test]
    public function the_job_honours_a_configured_connection(): void
    {
        Queue::fake();
        config([
            'threat-detection.queue.enabled' => true,
            'threat-detection.queue.connection' => 'redis',
        ]);

        $this->get('/infra?q=' . urlencode(self::SQLI));

        Queue::assertPushed(StoreThreatLog::class, fn ($job) => $job->connection === 'redis');
    }

    /**
     * The job's own failure behaviour. It has tries = 3 and a backoff, so a
     * failed insert has to propagate for the queue worker to retry it — a job
     * that swallowed the exception would report success having written
     * nothing, which is the same silent-failure class the package fixed
     * elsewhere.
     */
    #[Test]
    public function the_job_rethrows_a_failed_insert_so_the_queue_can_retry_it(): void
    {
        Log::spy();
        Schema::dropIfExists('threat_logs');

        $job = new StoreThreatLog([[
            'ip_address' => '203.0.113.1', 'url' => 'https://example.com/x', 'user_agent' => 'PHPUnit',
            'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
            'confidence_score' => 50, 'confidence_label' => 'high', 'user_id' => null,
            'created_at' => now(), 'updated_at' => now(),
        ]]);

        $this->expectException(\Throwable::class);

        try {
            $job->handle();
        } finally {
            Log::shouldHaveReceived('error')
                ->withArgs(fn ($m) => str_contains($m, 'StoreThreatLog job failed'))
                ->once();
        }
    }

    #[Test]
    public function the_job_is_configured_to_retry_rather_than_to_give_up_on_first_failure(): void
    {
        $job = new StoreThreatLog([]);

        $this->assertGreaterThan(1, $job->tries);
        $this->assertNotEmpty($job->backoff);
    }

    /**
     * The job's notification branch, which had never executed. A webhook
     * failure has to stay inside the job: the row is already written by then,
     * and losing it to a Slack outage would be the worst possible trade.
     */
    #[Test]
    public function the_job_sends_the_slack_notification_after_writing_the_row(): void
    {
        Http::fake(['*' => Http::response('ok', 200)]);

        $job = new StoreThreatLog(
            [[
                'ip_address' => '203.0.113.1', 'url' => 'https://example.com/x', 'user_agent' => 'PHPUnit',
                'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
                'confidence_score' => 50, 'confidence_label' => 'high', 'user_id' => null,
                'created_at' => now(), 'updated_at' => now(),
            ]],
            [
                'webhook_url' => 'https://hooks.slack.example/services/T/B/X',
                'alert_data' => [
                    'ip_address' => '203.0.113.1', 'url' => 'https://example.com/x',
                    'type' => '[middleware] XSS Script Tag', 'threat_level' => 'high',
                    'action_taken' => 'logged', 'user_agent' => 'PHPUnit',
                ],
            ]
        );

        $job->handle();

        $this->assertSame(1, DB::table('threat_logs')->count());
        Http::assertSent(fn ($request) => str_contains($request->url(), 'hooks.slack.example'));
    }

    #[Test]
    public function a_failing_webhook_does_not_lose_the_row_the_job_already_wrote(): void
    {
        Log::spy();
        Http::fake(fn () => throw new ConnectionException('timed out'));

        $job = new StoreThreatLog(
            [[
                'ip_address' => '203.0.113.1', 'url' => 'https://example.com/x', 'user_agent' => 'PHPUnit',
                'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
                'confidence_score' => 50, 'confidence_label' => 'high', 'user_id' => null,
                'created_at' => now(), 'updated_at' => now(),
            ]],
            ['webhook_url' => 'https://hooks.slack.example/x', 'alert_data' => ['ip_address' => '203.0.113.1']]
        );

        $job->handle();

        $this->assertSame(1, DB::table('threat_logs')->count());
        Log::shouldHaveReceived('error')
            ->withArgs(fn ($m) => str_contains($m, 'StoreThreatLog notification failed'))
            ->once();
    }

    #[Test]
    public function the_job_sends_nothing_when_no_webhook_is_configured(): void
    {
        Http::fake();

        $job = new StoreThreatLog(
            [[
                'ip_address' => '203.0.113.1', 'url' => 'https://example.com/x', 'user_agent' => 'PHPUnit',
                'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
                'confidence_score' => 50, 'confidence_label' => 'high', 'user_id' => null,
                'created_at' => now(), 'updated_at' => now(),
            ]],
            ['webhook_url' => null, 'alert_data' => []]
        );

        $job->handle();

        Http::assertNothingSent();
        $this->assertSame(1, DB::table('threat_logs')->count());
    }

    // ── the synchronous notification path ──────────────────────────────────

    /**
     * The non-queued counterpart, which had also never run: the service sends
     * the webhook itself when the queue is off.
     */
    #[Test]
    public function the_synchronous_path_sends_the_slack_notification_itself(): void
    {
        Http::fake(['*' => Http::response('ok', 200)]);
        config([
            'threat-detection.queue.enabled' => false,
            'threat-detection.notifications.enabled' => true,
            'threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/services/T/B/X',
            'threat-detection.notifications.notify_levels' => ['high'],
        ]);

        $this->get('/infra?q=' . urlencode(self::SQLI))->assertStatus(200);

        Http::assertSent(fn ($request) => str_contains($request->url(), 'hooks.slack.example'));
    }

    #[Test]
    public function a_level_outside_notify_levels_sends_nothing(): void
    {
        Http::fake();
        config([
            'threat-detection.notifications.enabled' => true,
            'threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/x',
            'threat-detection.notifications.notify_levels' => ['high'],
        ]);

        // A low-severity match only.
        $this->get('/infra?q=' . urlencode('{{ 1 }}'))->assertStatus(200);

        Http::assertNothingSent();
    }

    #[Test]
    public function notifications_disabled_sends_nothing_however_severe_the_threat(): void
    {
        Http::fake();
        config([
            'threat-detection.notifications.enabled' => false,
            'threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/x',
        ]);

        $this->get('/infra?q=' . urlencode(self::SQLI))->assertStatus(200);

        Http::assertNothingSent();
    }
}
