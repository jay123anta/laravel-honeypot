<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use JayAnta\ThreatDetection\Services\ConfidenceScorer;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Confidence scoring, asserted by direction rather than by number.
 *
 * ConfidenceScorerTest already pins the arithmetic: it asserts that one match
 * scores 20, that an attack-tool user agent adds 25, and so on. Those tests
 * are exact and brittle in the useful way — they catch an accidental change to
 * a constant.
 *
 * What they cannot catch is a change that keeps every constant and breaks the
 * ordering: two bonuses swapped, a comparison inverted, a clamp applied before
 * an addition instead of after. This file asserts the properties that have to
 * hold whatever the numbers are — more evidence never scores lower than less,
 * a higher-weighted context never scores lower than a lower-weighted one,
 * strict never scores below balanced, and so on.
 *
 * It also holds the arithmetic for the relaxed-mode floor, which is where the
 * scale and the threshold disagree.
 */
class ConfidenceScoringDirectionTest extends TestCase
{
    private ConfidenceScorer $scorer;

    /**
     * The floors detectAndLogFromRequest() applies per mode. Mirrored here
     * deliberately: if the source changes one of these, the direction tests
     * below should be re-derived rather than silently tracking it.
     */
    private const MODE_FLOOR = ['strict' => 0, 'balanced' => 10, 'relaxed' => 25];

    protected function setUp(): void
    {
        parent::setUp();

        $this->scorer = new ConfidenceScorer;
    }

    /**
     * @param  array<int, array{0: string, 1: string, 2: string}>  $matches
     */
    private function score(array $matches, array $weights = [], bool $tool = false, string $mode = 'balanced'): int
    {
        return $this->scorer->calculate($matches, $weights, $tool, $mode)['score'];
    }

    /** @return array<int, array{0: string, 1: string, 2: string}> */
    private function signals(int $count, string $level = 'high'): array
    {
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = ["Label {$i}", $level, 'middleware'];
        }

        return $out;
    }

    /** @return array<string, float> every label weighted the same */
    private function weights(array $matches, float $weight): array
    {
        return array_fill_keys(array_column($matches, 0), $weight);
    }

    // ── direction: pattern count ────────────────────────────────────────────

    #[Test]
    public function more_matching_patterns_never_score_lower_than_fewer(): void
    {
        $previous = -1;

        foreach (range(1, 8) as $count) {
            $score = $this->score($this->signals($count));

            $this->assertGreaterThanOrEqual(
                $previous,
                $score,
                "{$count} matches scored lower than " . ($count - 1)
            );
            $previous = $score;
        }
    }

    #[Test]
    public function the_second_and_third_extra_matches_each_raise_the_score(): void
    {
        $one = $this->score($this->signals(1));
        $two = $this->score($this->signals(2));
        $three = $this->score($this->signals(3));

        $this->assertGreaterThan($one, $two);
        $this->assertGreaterThan($two, $three);
    }

    /**
     * The extra-match bonus is capped at three, so a fifth match must not move
     * the score. Asserted as "stops rising", not as a number.
     */
    #[Test]
    public function extra_matches_stop_raising_the_score_once_the_cap_is_reached(): void
    {
        $four = $this->score($this->signals(4));

        foreach ([5, 6, 10, 25] as $count) {
            $this->assertSame($four, $this->score($this->signals($count)), "{$count} matches moved past the cap");
        }
    }

    #[Test]
    public function no_matches_at_all_scores_zero_and_labels_low(): void
    {
        $result = $this->scorer->calculate([], [], true, 'strict');

        $this->assertSame(0, $result['score']);
        $this->assertSame('low', $result['label']);
    }

    // ── direction: severity ─────────────────────────────────────────────────

    #[Test]
    public function a_high_severity_match_scores_above_the_same_number_of_low_severity_matches(): void
    {
        foreach (range(1, 4) as $count) {
            $this->assertGreaterThan(
                $this->score($this->signals($count, 'low')),
                $this->score($this->signals($count, 'high')),
                "{$count} high-severity matches did not outscore the same number of low"
            );
        }
    }

    #[Test]
    public function one_high_severity_match_among_low_ones_raises_the_score(): void
    {
        $allLow = $this->signals(3, 'low');
        $oneHigh = $allLow;
        $oneHigh[1][1] = 'high';

        $this->assertGreaterThan($this->score($allLow), $this->score($oneHigh));
    }

    /** The bonus applies once, however many high-severity matches there are. */
    #[Test]
    public function the_high_severity_bonus_is_not_paid_twice(): void
    {
        $oneHigh = $this->signals(3, 'low');
        $oneHigh[0][1] = 'high';

        $this->assertSame($this->score($this->signals(3, 'high')), $this->score($oneHigh));
    }

    // ── direction: context weight ───────────────────────────────────────────

    /**
     * @return array<string, array{0: float, 1: float}> lower, higher
     */
    public static function weightPairs(): array
    {
        return [
            'body vs headers' => [1.0, 1.3],
            'body vs query' => [1.0, 1.5],
            'headers vs query' => [1.3, 1.5],
            'body vs path' => [1.0, 1.5],
        ];
    }

    #[Test]
    #[DataProvider('weightPairs')]
    public function a_more_suspicious_context_never_scores_lower_than_a_less_suspicious_one(float $lower, float $higher): void
    {
        $matches = $this->signals(2);

        $this->assertGreaterThanOrEqual(
            $this->score($matches, $this->weights($matches, $lower)),
            $this->score($matches, $this->weights($matches, $higher))
        );
    }

    /**
     * The bonus is a threshold, not a multiplier: anything above 1.0 earns the
     * same flat amount. Worth pinning explicitly, because the config presents
     * context_weights as though they scale (1.3 vs 1.5), and they do not.
     */
    #[Test]
    public function every_context_weight_above_one_earns_the_same_flat_bonus(): void
    {
        $matches = $this->signals(1);

        $baseline = $this->score($matches, $this->weights($matches, 1.0));
        $weighted = array_map(
            fn (float $w) => $this->score($matches, $this->weights($matches, $w)),
            [1.1, 1.3, 1.5, 5.0, 100.0]
        );

        $this->assertGreaterThan($baseline, $weighted[0]);
        $this->assertSame([$weighted[0]], array_values(array_unique($weighted)), 'the weight value changed the bonus');
    }

    #[Test]
    public function a_weight_of_exactly_one_earns_no_bonus(): void
    {
        $matches = $this->signals(1);

        $this->assertSame(
            $this->score($matches, []),
            $this->score($matches, $this->weights($matches, 1.0))
        );
    }

    #[Test]
    public function a_weight_below_one_does_not_reduce_the_score(): void
    {
        $matches = $this->signals(1);

        $this->assertSame(
            $this->score($matches, []),
            $this->score($matches, $this->weights($matches, 0.2))
        );
    }

    // ── direction: attack-tool user agent ───────────────────────────────────

    #[Test]
    public function an_attack_tool_user_agent_never_lowers_the_score(): void
    {
        foreach (range(1, 5) as $count) {
            $matches = $this->signals($count);

            $this->assertGreaterThanOrEqual(
                $this->score($matches, [], false),
                $this->score($matches, [], true)
            );
        }
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function userAgents(): array
    {
        return [
            'sqlmap' => ['sqlmap/1.7.2#stable (https://sqlmap.org)', true],
            'nikto' => ['Mozilla/5.0 (Nikto/2.5.0)', true],
            'nmap' => ['Mozilla/5.0 Nmap Scripting Engine', true],
            'burp' => ['Mozilla/5.0 burp collaborator', true],
            'owasp zap spelled out' => ['Mozilla/5.0 (OWASP ZAP)', true],
            'zaproxy' => ['zaproxy/2.14', true],
            'metasploit' => ['Metasploit RSpec', true],
            'ordinary chrome' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36', false],
            'ordinary firefox' => ['Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0', false],
            'googlebot' => ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', false],
            // The reason 'zap' is not matched bare: a legitimate integration.
            'zapier' => ['Zapier/1.0 (+https://zapier.com)', false],
            'an empty user agent' => ['', false],
            'a curl download' => ['curl/8.4.0', false],
        ];
    }

    #[Test]
    #[DataProvider('userAgents')]
    public function the_attack_tool_check_recognises_the_tool_and_leaves_ordinary_clients_alone(string $ua, bool $expected): void
    {
        $this->assertSame($expected, $this->scorer->isAttackToolUserAgent($ua));
    }

    // ── direction: detection mode ───────────────────────────────────────────

    #[Test]
    public function strict_scores_at_or_above_balanced_which_scores_at_or_above_relaxed(): void
    {
        foreach (range(1, 5) as $count) {
            $matches = $this->signals($count);

            $strict = $this->score($matches, [], false, 'strict');
            $balanced = $this->score($matches, [], false, 'balanced');
            $relaxed = $this->score($matches, [], false, 'relaxed');

            $this->assertGreaterThanOrEqual($balanced, $strict, "strict < balanced at {$count} matches");
            $this->assertGreaterThanOrEqual($relaxed, $balanced, "balanced < relaxed at {$count} matches");
        }
    }

    #[Test]
    public function an_unknown_mode_scores_the_same_as_balanced(): void
    {
        $matches = $this->signals(2);

        $this->assertSame(
            $this->score($matches, [], false, 'balanced'),
            $this->score($matches, [], false, 'paranoid')
        );
    }

    // ── labels follow the score, monotonically ─────────────────────────────

    #[Test]
    public function the_label_never_goes_down_as_the_score_goes_up(): void
    {
        $rank = ['low' => 0, 'medium' => 1, 'high' => 2, 'very_high' => 3];
        $previous = -1;

        foreach (range(0, 100) as $score) {
            $label = $this->scorer->scoreToLabel($score);

            $this->assertArrayHasKey($label, $rank, "unknown label '{$label}' at score {$score}");
            $this->assertGreaterThanOrEqual($previous, $rank[$label], "the label fell at score {$score}");
            $previous = $rank[$label];
        }
    }

    #[Test]
    public function every_label_band_is_reachable(): void
    {
        $seen = [];
        foreach (range(0, 100) as $score) {
            $seen[$this->scorer->scoreToLabel($score)] = true;
        }

        $this->assertSame(['low', 'medium', 'high', 'very_high'], array_keys($seen));
    }

    #[Test]
    public function the_score_stays_inside_zero_and_one_hundred_under_every_combination(): void
    {
        foreach ([0, 1, 3, 10, 50] as $count) {
            foreach (['strict', 'balanced', 'relaxed'] as $mode) {
                foreach ([false, true] as $tool) {
                    foreach ([0.0, 1.0, 1.5, 99.0] as $weight) {
                        $matches = $this->signals($count);
                        $score = $this->score($matches, $this->weights($matches, $weight), $tool, $mode);

                        $this->assertGreaterThanOrEqual(0, $score);
                        $this->assertLessThanOrEqual(100, $score);
                    }
                }
            }
        }
    }

    // ── the mode floors, which is where the scale disagrees with itself ────

    /**
     * The property BUG 5 broke: a single high-severity detection clears its own
     * mode's floor, from any context.
     *
     * Relaxed used to set that floor at 40 while capping a lone match at 35
     * (25 from a body), so one pattern could never be logged in relaxed mode
     * however severe it was — unless the client carried an attack-tool user
     * agent, that is, unless the attacker announced themselves. The floor is
     * now 25, the lowest score a lone high-severity match can produce.
     *
     * Asserted from every context, including the body, which is the weakest
     * and therefore the one that fixes the bound.
     */
    #[Test]
    public function one_high_severity_match_clears_the_floor_of_every_detection_mode(): void
    {
        $belowFloor = [];

        foreach (self::MODE_FLOOR as $mode => $floor) {
            foreach (['body' => 1.0, 'headers' => 1.3, 'query' => 1.5, 'path' => 1.5] as $context => $weight) {
                $matches = $this->signals(1);
                $score = $this->score($matches, $this->weights($matches, $weight), false, $mode);

                if ($score < $floor) {
                    $belowFloor["{$mode}/{$context}"] = "scored {$score}, floor is {$floor}";
                }
            }
        }

        $this->assertSame(
            [],
            $belowFloor,
            'a lone high-severity detection is silently discarded: ' . json_encode($belowFloor)
        );
    }

    /**
     * The same statement from the other side, and the reason the bug is not
     * "relaxed mode logs nothing": two simultaneous high-severity matches do
     * clear the floor. Relaxed is, in effect, a two-signature minimum.
     */
    #[Test]
    public function two_high_severity_matches_clear_the_relaxed_floor(): void
    {
        $matches = $this->signals(2);

        $this->assertGreaterThanOrEqual(
            self::MODE_FLOOR['relaxed'],
            $this->score($matches, $this->weights($matches, 1.0), false, 'relaxed')
        );
    }

    #[Test]
    public function an_attack_tool_user_agent_lifts_a_lone_match_over_the_relaxed_floor(): void
    {
        $matches = $this->signals(1);

        $this->assertGreaterThanOrEqual(
            self::MODE_FLOOR['relaxed'],
            $this->score($matches, $this->weights($matches, 1.0), true, 'relaxed')
        );
    }
}
