<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD_AUDIT.md "Not verified" item 6: the multipart / file-upload scanning path.
 *
 * Two pieces of code decide what of an upload gets looked at, and neither had
 * a test:
 *
 *   buildPayloadSegments() strips file keys out of the POST data, so file
 *   *fields* are not scanned as if they were text; and
 *   rawBody() returns '' outright for a multipart content type, because
 *   php://input is not readable for multipart and file bytes are not worth
 *   scanning one by one.
 *
 * Uploads are attacker-controlled by definition, so the boundary those two
 * draw is worth pinning: what still gets scanned, what deliberately does not,
 * and that neither case can break the request.
 */
class MultipartUploadScanningTest extends TestCase
{
    private const SQLI = "' UNION SELECT password FROM users--";

    private const BOUNDARY = 'multipart/form-data; boundary=----ThreatDetectionTestBoundary';

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

        Route::middleware('threat-detect')->post('/upload', fn () => response('OK', 200));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /** @param array<string, UploadedFile> $files */
    private function upload(array $params, array $files = []): TestResponse
    {
        return $this->call('POST', '/upload', $params, [], $files, [
            'CONTENT_TYPE' => self::BOUNDARY,
        ]);
    }

    /** @return string[] the labels logged, without their source tag */
    private function loggedLabels(): array
    {
        return DB::table('threat_logs')
            ->pluck('type')
            ->map(fn ($t) => preg_replace('/^\[[a-z-]+\] /', '', $t))
            ->values()
            ->all();
    }

    private function assertLogged(string $label): void
    {
        $this->assertContains(
            $label,
            $this->loggedLabels(),
            "expected '{$label}'; got: " . (implode(', ', $this->loggedLabels()) ?: 'nothing at all')
        );
    }

    /**
     * The control this whole file rests on: the route, the middleware and the
     * detector are all live, so a "nothing was logged" assertion below means
     * something. Same payload, same route, ordinary form encoding.
     */
    #[Test]
    public function detection_is_live_on_this_route_for_an_ordinary_form_post(): void
    {
        $this->call('POST', '/upload', ['title' => self::SQLI], [], [], [
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        ])->assertStatus(200);

        $this->assertLogged('SQL Injection UNION');
    }

    /**
     * The property that matters most: stripping file keys must not take the
     * ordinary text fields with them. An upload form's text inputs are as
     * attacker-controlled as any other POST body.
     */
    #[Test]
    public function a_hostile_text_field_beside_a_file_upload_is_still_scanned(): void
    {
        $response = $this->upload(
            ['title' => self::SQLI, 'note' => 'holiday photo'],
            ['document' => UploadedFile::fake()->createWithContent('a.txt', 'harmless')]
        );

        $response->assertStatus(200);
        $this->assertLogged('SQL Injection UNION');
    }

    /**
     * Positive control for every "not scanned" test below: an ordinary upload
     * with nothing hostile in it logs nothing. Without this, "no detection"
     * would be satisfied by detection being off altogether.
     */
    #[Test]
    public function an_ordinary_upload_is_not_flagged(): void
    {
        $response = $this->upload(
            ['title' => 'Holiday photo', 'note' => 'Taken in Shillong'],
            ['document' => UploadedFile::fake()->createWithContent('photo.jpg', 'binary-ish content')]
        );

        $response->assertStatus(200);
        $this->assertSame([], $this->loggedLabels());
    }

    /**
     * File *content* is deliberately not scanned. This is a design decision,
     * not an oversight — scanning uploaded bytes would flag every SQL dump,
     * log archive and source tarball a user legitimately uploads — but it was
     * undocumented and untested, so it is pinned here rather than left to be
     * rediscovered.
     */
    #[Test]
    public function the_contents_of_an_uploaded_file_are_deliberately_not_scanned(): void
    {
        $response = $this->upload(
            ['title' => 'db backup'],
            ['document' => UploadedFile::fake()->createWithContent(
                'dump.sql',
                "' UNION SELECT password FROM users-- <script>alert(1)</script>"
            )]
        );

        $response->assertStatus(200);
        $this->assertSame(
            [],
            $this->loggedLabels(),
            'file bytes are now being scanned, which will flag every uploaded SQL dump'
        );
    }

    /**
     * The client-supplied filename travels in the multipart headers, not in
     * the POST data, so it is not scanned either. Recorded because it is the
     * one piece of an upload that is both attacker-chosen and short enough to
     * scan cheaply — a candidate for a future finding, pinned here so a change
     * in either direction is deliberate.
     */
    #[Test]
    public function a_hostile_client_filename_is_not_scanned(): void
    {
        $response = $this->upload(
            ['title' => 'report'],
            ['document' => UploadedFile::fake()->createWithContent(
                "'; DROP TABLE users--.txt",
                'harmless'
            )]
        );

        $response->assertStatus(200);
        $this->assertSame([], $this->loggedLabels());
    }

    /**
     * A file field whose *key* is hostile. The key is what gets stripped, and
     * array_flip on it must not misbehave on an odd name.
     */
    #[Test]
    public function a_hostile_file_field_name_does_not_break_the_request(): void
    {
        $response = $this->upload(
            ['title' => 'report'],
            ["doc'; DROP TABLE--" => UploadedFile::fake()->createWithContent('a.txt', 'harmless')]
        );

        $response->assertStatus(200);
    }

    /**
     * The passive invariant, on the path most likely to throw: many files,
     * a large one, and no file at all despite the multipart content type.
     */
    #[Test]
    public function a_multipart_request_always_reaches_the_application(): void
    {
        $this->upload(
            ['title' => 'batch'],
            [
                'a' => UploadedFile::fake()->createWithContent('a.txt', str_repeat('A', 200000)),
                'b' => UploadedFile::fake()->createWithContent('b.txt', 'small'),
                'c' => UploadedFile::fake()->createWithContent('c.txt', ''),
            ]
        )->assertStatus(200);

        $this->upload(['title' => 'nothing attached'])->assertStatus(200);

        $this->call('POST', '/upload', [], [], [], ['CONTENT_TYPE' => self::BOUNDARY])
            ->assertStatus(200);
    }

    /**
     * A request that *declares* multipart but carries an ordinary body.
     *
     * rawBody() keys off the Content-Type header alone, so the raw segment is
     * skipped here. That is not an evasion in production — PHP will not
     * populate $_POST from a body that does not match the declared boundary
     * either, so the payload does not reach the application any more than it
     * reaches the scanner — but the test framework builds the request
     * directly, so the two diverge and this pins which behaviour is ours.
     *
     * The payload below is placed in the POST data, which is scanned, so the
     * request is still caught. If it were only in the raw body it would not
     * be, and that limit is stated in TD_AUDIT.md rather than hidden here.
     */
    #[Test]
    public function a_body_declared_multipart_is_still_scanned_through_its_post_data(): void
    {
        $response = $this->upload(['q' => self::SQLI]);

        $response->assertStatus(200);
        $this->assertLogged('SQL Injection UNION');
    }
}
