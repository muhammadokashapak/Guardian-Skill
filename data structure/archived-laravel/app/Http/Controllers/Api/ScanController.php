<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Models\Scan;

class ScanController extends Controller {
    public function store(Project $project) {
        $scan = Scan::create([
            'project_id' => $project->id,
            'status' => 'COMPLETED',
            'scan_type' => 'FULL',
            'started_at' => now(),
            'finished_at' => now(),
        ]);
        return response()->json(['scan_id' => $scan->id, 'status' => 'COMPLETED'], 201);
    }

    public function show(Scan $scan) {
        return response()->json($scan->load('findings'));
    }
}
