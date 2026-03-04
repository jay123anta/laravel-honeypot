<?php

use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Http\Controllers\ThreatLogController;

Route::prefix(config('threat-detection.api.prefix', 'api/threat-detection'))
    ->middleware(config('threat-detection.api.middleware', ['api']))
    ->group(function () {

        // List and search threats
        Route::get('/threats', [ThreatLogController::class, 'index']);

        // Get single threat details
        Route::get('/threats/{id}', [ThreatLogController::class, 'show']);

        // Statistics and summaries
        Route::get('/stats', [ThreatLogController::class, 'stats']);
        Route::get('/summary', [ThreatLogController::class, 'summary']);
        Route::get('/live-count', [ThreatLogController::class, 'liveCount']);

        // Analysis endpoints
        Route::get('/by-country', [ThreatLogController::class, 'byCountry']);
        Route::get('/by-cloud-provider', [ThreatLogController::class, 'byCloudProvider']);
        Route::get('/top-ips', [ThreatLogController::class, 'topIps']);
        Route::get('/timeline', [ThreatLogController::class, 'timeline']);

        // IP statistics
        Route::get('/ip-stats', [ThreatLogController::class, 'ipStats']);

        // Correlation analysis
        Route::get('/correlation', [ThreatLogController::class, 'correlation']);

        // Export
        Route::get('/export', [ThreatLogController::class, 'export']);

        // False positive reporting
        Route::post('/threats/{id}/false-positive', [ThreatLogController::class, 'markFalsePositive']);

        // Exclusion rules management
        Route::get('/exclusion-rules', [ThreatLogController::class, 'exclusionRules']);
        Route::delete('/exclusion-rules/{id}', [ThreatLogController::class, 'deleteExclusionRule']);
    });
