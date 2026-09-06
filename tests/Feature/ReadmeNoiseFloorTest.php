<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The README publishes a subset of the measured noise floor, so that someone
 * evaluating the package learns what it flags on legitimate content before
 * installing rather than after.
 *
 * A documented false-positive table that has drifted from the measured one is
 * worse than none at all: it is a promise the code no longer keeps, in the one
 * section a sceptical reader is most likely to check. So every row published in
 * the README is checked against `LegitimateTrafficCorpusTest::untunedNoiseFloor()`,
 * which is the same array that test asserts against.
 *
 * If a pattern change moves the floor, the corpus test fails first and names
 * the change; this one then fails until the README is brought along.
 */
class ReadmeNoiseFloorTest extends TestCase
{
    private const START = '<!-- noise-floor:start -->';

    private const END = '<!-- noise-floor:end -->';

    private function readme(): string
    {
        $path = __DIR__ . '/../../README.md';
        $this->assertFileExists($path);

        return (string) file_get_contents($path);
    }

    /** @return string[] the raw table rows between the markers */
    private function publishedRows(): array
    {
        $readme = $this->readme();

        $start = strpos($readme, self::START);
        $end = strpos($readme, self::END);

        $this->assertNotFalse($start, 'the noise-floor table markers are missing from README.md');
        $this->assertNotFalse($end, 'the noise-floor closing marker is missing from README.md');
        $this->assertGreaterThan($start, $end, 'the noise-floor markers are in the wrong order');

        $block = substr($readme, $start + strlen(self::START), $end - $start - strlen(self::START));

        $rows = [];
        foreach (explode("\n", $block) as $line) {
            $line = trim($line);
            // Skip the header row and the |---|---| separator.
            if (!str_starts_with($line, '|') || str_contains($line, '---') || str_contains($line, 'Perfectly legitimate')) {
                continue;
            }
            $rows[] = $line;
        }

        return $rows;
    }

    /**
     * Every label/severity the README claims must be one the corpus actually
     * produced. This is the assertion that catches a stale table.
     */
    #[Test]
    public function every_detection_the_readme_advertises_is_one_the_corpus_measured(): void
    {
        $measured = [];
        foreach (LegitimateTrafficCorpusTest::untunedNoiseFloor() as $labels) {
            foreach ($labels as $label) {
                $measured[] = $label;
            }
        }
        $measured = array_unique($measured);

        foreach ($this->publishedRows() as $row) {
            $cells = array_values(array_filter(array_map('trim', explode('|', $row)), fn ($c) => $c !== ''));
            $this->assertCount(2, $cells, "malformed README row: {$row}");

            // "`XSS Script Tag` / high" -> "XSS Script Tag/high"
            $claim = str_replace(['`', ' / ', ' /', '/ '], ['', '/', '/', '/'], $cells[1]);

            $this->assertContains(
                $claim,
                $measured,
                "README advertises '{$claim}', which the corpus never produced. "
                . 'Either the patterns moved or the table is stale. Measured: ' . implode(', ', $measured)
            );
        }
    }

    /**
     * The table must not be quietly emptied — that would pass the assertion
     * above vacuously while removing the disclosure it exists to make.
     */
    #[Test]
    public function the_readme_publishes_a_meaningful_number_of_examples(): void
    {
        $this->assertGreaterThanOrEqual(
            5,
            count($this->publishedRows()),
            'the published noise-floor table has been emptied or trimmed below the point of being useful'
        );
    }

    /**
     * And it must keep pointing at the fix. A disclosure with no remedy beside
     * it reads as a defect rather than a tuning step.
     */
    #[Test]
    public function the_disclosure_links_to_the_tuning_section(): void
    {
        $readme = $this->readme();

        $start = strpos($readme, self::START);
        $this->assertNotFalse($start);

        // The paragraphs immediately after the table must name the remedy.
        $after = substr($readme, $start, 2500);

        foreach (['safe_fields', 'content_paths', '#reducing-false-positives'] as $needle) {
            $this->assertStringContainsString(
                $needle,
                $after,
                "the noise-floor disclosure no longer points at '{$needle}'"
            );
        }
    }
}
