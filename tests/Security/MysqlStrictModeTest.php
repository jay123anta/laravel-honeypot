<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD_AUDIT.md "Not verified" items 2 and 3, closed on a real strict-mode server.
 *
 * The rest of the suite runs on sqlite, which treats a varchar width as
 * advisory and silently accepts an over-long value. Two audit findings turned
 * on what a *strict* engine does instead — TD-012 (an over-long geo value
 * aborting the enrichment loop) and TD-006 (an empty ip_address reaching a
 * NOT NULL column) — and neither could be observed there.
 *
 * These tests skip unless a MySQL/MariaDB server is reachable, so CI and a
 * plain `composer test` are unaffected. Point them at a scratch database:
 *
 *   THREAT_DETECTION_MYSQL=1 \
 *   THREAT_DETECTION_MYSQL_DATABASE=threat_detection_test \
 *   vendor/bin/phpunit tests/Security/MysqlStrictModeTest.php
 *
 * The database is created if it does not exist and the table is dropped
 * between tests. Nothing outside that database is touched.
 */
class MysqlStrictModeTest extends TestCase
{
    private const TABLE = 'threat_logs';

    protected function setUp(): void
    {
        parent::setUp();

        $this->skipUnlessMysqlIsReachable();
        $this->buildTable();
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('database.default', 'mysql_scratch');
        $app['config']->set('database.connections.mysql_scratch', [
            'driver' => 'mysql',
            'host' => env('THREAT_DETECTION_MYSQL_HOST', '127.0.0.1'),
            'port' => env('THREAT_DETECTION_MYSQL_PORT', '3306'),
            'database' => env('THREAT_DETECTION_MYSQL_DATABASE', 'threat_detection_test'),
            'username' => env('THREAT_DETECTION_MYSQL_USERNAME', 'root'),
            'password' => env('THREAT_DETECTION_MYSQL_PASSWORD', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'engine' => null,
        ]);
    }

    private function skipUnlessMysqlIsReachable(): void
    {
        if (env('THREAT_DETECTION_MYSQL') !== '1') {
            $this->markTestSkipped('Set THREAT_DETECTION_MYSQL=1 and point the connection at a scratch database to run these.');
        }

        try {
            DB::connection('mysql_scratch')->select('SELECT 1');
        } catch (\Throwable $e) {
            $this->markTestSkipped('No MySQL/MariaDB server answered: ' . $e->getMessage());
        }
    }

    private function buildTable(): void
    {
        Schema::dropIfExists(self::TABLE);

        DB::statement(
            'CREATE TABLE ' . self::TABLE . ' ('
            . 'id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,'
            . 'ip_address VARCHAR(255) NOT NULL,'
            . 'url TEXT NOT NULL,'
            . 'user_agent TEXT NULL,'
            . 'type TEXT NOT NULL,'
            . 'payload TEXT NULL,'
            . "threat_level VARCHAR(255) NOT NULL DEFAULT 'medium',"
            . "action_taken VARCHAR(255) NOT NULL DEFAULT 'logged',"
            . 'user_id BIGINT UNSIGNED NULL,'
            . 'country_code VARCHAR(5) NULL,'
            . 'country_name VARCHAR(100) NULL,'
            . 'city VARCHAR(100) NULL,'
            . 'isp VARCHAR(255) NULL,'
            . 'cloud_provider VARCHAR(50) NULL,'
            . 'is_foreign TINYINT(1) NOT NULL DEFAULT 0,'
            . 'is_cloud_ip TINYINT(1) NOT NULL DEFAULT 0,'
            . 'created_at TIMESTAMP NULL,'
            . 'updated_at TIMESTAMP NULL'
            . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
        );
    }

    protected function tearDown(): void
    {
        if (env('THREAT_DETECTION_MYSQL') === '1') {
            try {
                Schema::dropIfExists(self::TABLE);
            } catch (\Throwable $e) {
                // The skip path never built it.
            }
        }

        parent::tearDown();
    }

    private function seedRow(string $ip): int
    {
        return (int) DB::table(self::TABLE)->insertGetId([
            'ip_address' => $ip,
            'url' => '/login',
            'user_agent' => 'curl/8.0',
            'type' => 'SQL Injection',
            'threat_level' => 'high',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /**
     * The premise behind TD-012's severity: on this engine an over-long value
     * is an error, not a silent truncation. If this ever stops being true the
     * finding's consequence changes and the rest of these tests are moot.
     */
    #[Test]
    public function this_server_rejects_an_over_long_value_rather_than_truncating_it(): void
    {
        $id = $this->seedRow('203.0.113.10');

        $this->expectException(QueryException::class);

        DB::table(self::TABLE)->where('id', $id)->update([
            'country_name' => str_repeat('A', 300),
        ]);
    }

    /**
     * TD-012, on the engine where it mattered. A hostile provider returns 300
     * characters for a 100-character column; before the fix that update threw
     * and took the whole enrichment run down with it.
     */
    #[Test]
    public function an_oversized_geo_response_does_not_abort_enrichment_on_a_strict_server(): void
    {
        $first = $this->seedRow('203.0.113.10');
        $second = $this->seedRow('203.0.113.11');

        Http::fake([
            '*' => Http::response([
                'status' => 'success',
                'countryCode' => str_repeat('X', 50),
                'country' => str_repeat('A', 300),
                'city' => str_repeat('B', 300),
                'isp' => str_repeat('C', 900),
                'org' => str_repeat('D', 900),
            ], 200),
        ]);

        $exit = $this->artisan('threat-detection:enrich')->run();

        $this->assertSame(0, $exit, 'the enrichment run aborted on the oversized response');

        // Positive control: the run reached the *second* row. An abort on the
        // first would leave this one untouched, which is the actual finding.
        foreach ([$first, $second] as $id) {
            $row = DB::table(self::TABLE)->where('id', $id)->first();
            $this->assertNotNull($row->country_name, "row {$id} was never enriched");
            $this->assertSame(100, mb_strlen($row->country_name));
            $this->assertSame(5, mb_strlen($row->country_code));
            $this->assertSame(255, mb_strlen($row->isp));
        }
    }

    /**
     * TD-006's remaining question: what a strict server does with an empty
     * ip_address. The answer is that it stores it — NOT NULL does not mean
     * non-empty — so the export-side validation added for TD-005 is the only
     * thing standing between it and a generated `deny ;` directive.
     */
    #[Test]
    public function an_empty_ip_address_is_accepted_by_a_not_null_column(): void
    {
        $id = $this->seedRow('');

        $stored = DB::table(self::TABLE)->where('id', $id)->value('ip_address');

        $this->assertSame('', $stored, 'a NOT NULL varchar rejected the empty string, which would make TD-006 unreachable');
    }

    /**
     * And that having been stored, no export emits it. This is TD-005's fix
     * observed on the engine that can actually hold the value.
     */
    #[Test]
    public function an_empty_ip_address_never_reaches_a_generated_directive(): void
    {
        $this->seedRow('');
        $this->seedRow('203.0.113.77');

        foreach (['nginx', 'apache', 'plain'] as $format) {
            Artisan::call('threat-detection:export-blocklist', ['--format' => $format]);
            $output = Artisan::output();

            $this->assertStringContainsString('203.0.113.77', $output, "the {$format} export emitted nothing, so this proves nothing");
            $this->assertStringNotContainsString('deny ;', $output);
            $this->assertStringNotContainsString('Deny from' . "\n", $output);
            $this->assertDoesNotMatchRegularExpression('/^\s*$/m', trim($output), 'a blank record line was emitted');
        }
    }
}
