<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD-012 — the geo-enrichment round trip.
 *
 * threat-detection:enrich takes every attacking IP from the log, sends it to a
 * third party, and writes the answer back into the same row that the dashboard
 * and the CSV export read. Three separate questions: can the outbound request
 * be steered, can the response poison the row, and what does the transport
 * disclose.
 */
class GeoEnrichmentTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['cache.default' => 'array']);
        Cache::flush();
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function seedIp(string $ip): int
    {
        return DB::table('threat_logs')->insertGetId([
            'ip_address' => $ip, 'url' => 'https://example.com/x', 'user_agent' => 'UA',
            'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
            'confidence_score' => 90, 'confidence_label' => 'very_high', 'action_taken' => 'logged',
            'created_at' => now(), 'updated_at' => now(),
        ]);
    }

    // ── outbound: can the request be steered? ──────────────────────────────

    /**
     * The IP is interpolated into the provider URL, so anything but a bare
     * address is a path-traversal or parameter-injection primitive against
     * the provider request. fetchGeoData() validates with FILTER_VALIDATE_IP
     * and skips private and reserved ranges before the call.
     */
    #[Test]
    public function a_non_address_in_the_column_is_never_sent_to_the_provider(): void
    {
        Http::fake();

        foreach ([
            '../../admin', 'evil.tld', '1.2.3.4/../x', '1.2.3.4?x=y', '1.2.3.4#frag',
            'localhost', '127.0.0.1', '169.254.169.254', '10.1.2.3', '192.168.0.1',
            '', 'not-an-ip',
        ] as $value) {
            DB::table('threat_logs')->delete();
            Cache::flush();
            $this->seedIp($value);

            Artisan::call('threat-detection:enrich', ['--days' => 7]);
        }

        Http::assertNothingSent();
    }

    #[Test]
    public function a_public_address_is_sent_as_a_bare_path_segment(): void
    {
        Http::fake(['*' => Http::response(['countryCode' => 'US', 'country' => 'United States'])]);

        $this->seedIp('8.8.8.8');
        Artisan::call('threat-detection:enrich', ['--days' => 7]);

        Http::assertSent(fn ($request) => str_contains($request->url(), '/8.8.8.8?'));
    }

    // ── inbound: can the response poison the row? ──────────────────────────

    /**
     * TD-012. The provider's answer is written back with no length check, no
     * type check and no allow-list. country_name is a varchar(100) and
     * country_code a varchar(5).
     *
     * On MySQL in strict mode an over-long value raises, and the exception is
     * not caught — the update sits outside fetchGeoData()'s try/catch
     * (EnrichThreatLogsCommand.php:117) — so the command aborts part-way
     * through the loop, leaving the enrichment half done. In non-strict mode
     * the value is silently truncated instead.
     *
     * This matters more than it looks because the transport is cleartext HTTP
     * by default, so the "provider" is anyone on the path.
     */
    #[Test]
    public function an_oversized_provider_response_does_not_abort_the_command(): void
    {
        Http::fake(['*' => Http::response([
            'countryCode' => str_repeat('X', 500),
            'country' => str_repeat('Y', 5000),
            'city' => str_repeat('Z', 5000),
            'isp' => str_repeat('W', 5000),
            'org' => str_repeat('V', 5000),
        ])]);

        $this->seedIp('8.8.8.8');

        $exit = Artisan::call('threat-detection:enrich', ['--days' => 7]);

        $this->assertSame(0, $exit, 'the command failed on an over-long provider response');
    }

    /**
     * A response whose fields are not strings at all — an array, an object, a
     * number. The values go straight into an update().
     */
    #[Test]
    public function a_type_confused_provider_response_does_not_abort_the_command(): void
    {
        Http::fake(['*' => Http::response([
            'countryCode' => ['US', 'GB'],
            'country' => ['nested' => 'object'],
            'city' => 12345,
            'isp' => true,
            'org' => null,
        ])]);

        $this->seedIp('8.8.8.8');

        $exit = Artisan::call('threat-detection:enrich', ['--days' => 7]);

        $this->assertSame(0, $exit, 'the command failed on a type-confused provider response');
    }

    /**
     * The stored value is rendered in the dashboard and exported to CSV, so a
     * hostile provider response is the one path by which a third party can put
     * arbitrary text into those. The CSV sanitizer covers it; this asserts the
     * value at least does not arrive as something other than text.
     */
    #[Test]
    public function a_hostile_provider_response_is_stored_as_text_and_nothing_else(): void
    {
        Http::fake(['*' => Http::response([
            'countryCode' => 'XX',
            'country' => "=cmd|'/c calc'!A0",
            'city' => '<script>window.__pwned=1</script>',
            'isp' => 'Evil ISP',
            'org' => 'Evil Org',
        ])]);

        $id = $this->seedIp('8.8.8.8');
        Artisan::call('threat-detection:enrich', ['--days' => 7]);

        $row = DB::table('threat_logs')->find($id);

        $this->assertIsString($row->country_name);
        $this->assertIsString($row->city);
    }

    // ── transport ──────────────────────────────────────────────────────────

    /**
     * TD-013 — the default provider endpoint is cleartext HTTP.
     *
     * ip-api.com's free tier is HTTP-only, so this is a deliberate trade
     * rather than an oversight, and the command prints a warning naming the
     * provider and the transport before it sends anything. What it means is
     * still worth stating plainly: every attacking IP the application has seen
     * is disclosed to anyone on the path, and the response — which is written
     * into the database — is chosen by them too.
     */
    #[Test]
    public function the_default_geo_endpoint_uses_an_encrypted_transport(): void
    {
        $shipped = require __DIR__ . '/../../config/threat-detection.php';

        $this->assertStringStartsWith(
            'https://',
            $shipped['enrichment']['endpoint'],
            'threat IPs and the response that is stored travel in cleartext by default'
        );
    }

    /** The mitigation that is present: the operator is told, before it happens. */
    #[Test]
    public function the_command_warns_that_addresses_leave_over_cleartext(): void
    {
        Http::fake(['*' => Http::response(['countryCode' => 'US'])]);
        $this->seedIp('8.8.8.8');

        // Artisan::call rather than the PendingCommand, so the whole output is
        // one string — both phrases live on the same line, and
        // expectsOutputToContain matches them against separate lines.
        $this->assertSame(0, Artisan::call('threat-detection:enrich', ['--days' => 7]));

        $output = Artisan::output();

        $this->assertStringContainsString('Provider: http://ip-api.com/json', $output);
        $this->assertStringContainsString('sent to this third party', $output);
        $this->assertStringContainsString('cleartext HTTP', $output);
    }
}
