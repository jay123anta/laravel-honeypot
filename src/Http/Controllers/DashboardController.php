<?php

namespace JayAnta\ThreatDetection\Http\Controllers;

use Illuminate\Routing\Controller;

class DashboardController extends Controller
{
    public function index()
    {
        return view('threat-detection::dashboard', [
            'apiPrefix' => '/' . ltrim(config('threat-detection.api.prefix', 'api/threat-detection'), '/'),
        ]);
    }
}
