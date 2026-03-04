<?php

namespace JayAnta\ThreatDetection\Services;

class ConfidenceScorer
{
    /**
     * Known attack tool user-agent keywords (high-severity scanners).
     */
    private array $attackTools = [
        'sqlmap', 'nikto', 'nmap', 'acunetix', 'nessus', 'openvas',
        'nuclei', 'metasploit', 'w3af', 'havij', 'masscan', 'zgrab',
        'burp', 'zap',
    ];

    /**
     * Calculate confidence score for a set of threat matches on a single request.
     *
     * @param array  $matches         Array of [label, threatLevel, sourceTag] tuples
     * @param array  $contextWeights  Map of label => weight multiplier from context
     * @param bool   $hasAttackToolUA Whether the user-agent matched a known attack tool
     * @param string $sensitivityMode 'strict' | 'balanced' | 'relaxed'
     * @return array{score: int, label: string}
     */
    public function calculate(
        array $matches,
        array $contextWeights = [],
        bool $hasAttackToolUA = false,
        string $sensitivityMode = 'balanced'
    ): array {
        if (empty($matches)) {
            return ['score' => 0, 'label' => 'low'];
        }

        $score = 0;

        // Base score: first pattern match
        $score += 20;

        // Additional pattern matches (max 3 extra = +45)
        $extraMatches = min(count($matches) - 1, 3);
        $score += $extraMatches * 15;

        // High-severity pattern bonus
        foreach ($matches as [$label, $level, $source]) {
            if ($level === 'high') {
                $score += 15;
                break; // Only count once
            }
        }

        // Context weight bonus (patterns found in query/headers score higher)
        foreach ($matches as [$label, $level, $source]) {
            $weight = $contextWeights[$label] ?? 1.0;
            if ($weight > 1.0) {
                $score += 10;
                break; // Only count once
            }
        }

        // Attack tool user-agent bonus
        if ($hasAttackToolUA) {
            $score += 25;
        }

        // Sensitivity mode adjustment
        $score += match ($sensitivityMode) {
            'strict' => 10,
            'relaxed' => -10,
            default => 0,
        };

        // Clamp to 0-100
        $score = max(0, min(100, $score));

        return [
            'score' => $score,
            'label' => $this->scoreToLabel($score),
        ];
    }

    /**
     * Check if a user-agent matches a known attack tool.
     */
    public function isAttackToolUserAgent(string $userAgent): bool
    {
        $ua = strtolower($userAgent);

        foreach ($this->attackTools as $tool) {
            if (str_contains($ua, $tool)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Map numeric score to categorical label.
     */
    public function scoreToLabel(int $score): string
    {
        return match (true) {
            $score >= 76 => 'very_high',
            $score >= 51 => 'high',
            $score >= 26 => 'medium',
            default => 'low',
        };
    }
}
