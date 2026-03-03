<?php

use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Http\Controllers\DashboardController;

Route::prefix(config('threat-detection.dashboard.path', 'threat-detection'))
    ->middleware(config('threat-detection.dashboard.middleware', ['web', 'auth']))
    ->group(function () {
        Route::get('/', [DashboardController::class, 'index'])
            ->name('threat-detection.dashboard');
    });
