<?php

use Illuminate\Support\Facades\Route;
use Security\Honeypot\Controllers\HoneypotController;

// Route::middleware(['web'])->prefix('honeypot')->group(function () {
//     Route::get('/dashboard', [HoneypotController::class, 'dashboard'])->name('honeypot.dashboard');
//     Route::get('/logs', [HoneypotController::class, 'index'])->name('honeypot.logs');
//     Route::get('/test', function () {
//         return 'Honeypot Route Working!';
//     });
// });

// Route::middleware(['web'])->prefix('honeypot')->group(function () {
//     Route::get('/dashboard', [\Security\Honeypot\Controllers\HoneypotController::class, 'summary'])->name('honeypot.dashboard');
//     Route::get('/logs', [\Security\Honeypot\Controllers\HoneypotController::class, 'index'])->name('honeypot.logs');
// });


Route::middleware(['web', 'honeypot'])->prefix('honeypot')->group(function () {
    Route::get('/dashboard', [\Security\Honeypot\Controllers\HoneypotController::class, 'dashboard'])->name('honeypot.dashboard');
    Route::get('/export', [\Security\Honeypot\Controllers\HoneypotController::class, 'exportCsv'])->name('honeypot.export');
});