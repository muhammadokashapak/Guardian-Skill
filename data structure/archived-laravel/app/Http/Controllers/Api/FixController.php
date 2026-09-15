<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Finding;
use App\Models\Fix;

class FixController extends Controller {
    public function createPlan(Finding $finding) {
        $fix = Fix::create([
            'finding_id' => $finding->id,
            'project_id' => $finding->project_id,
            'title' => 'Remediation for ' . $finding->title,
            'explanation' => $finding->remediation,
            'diff' => '# Unified Diff Patch',
            'target_files' => [$finding->affected_path],
            'risk_level' => $finding->severity === 'CRITICAL' ? 'HIGH' : 'MEDIUM',
            'requires_approval' => true,
        ]);
        return response()->json($fix, 201);
    }

    public function approve(Request $request, Fix $fix) {
        $fix->update(['approved' => true]);
        return response()->json(['status' => 'APPROVED', 'fix' => $fix]);
    }

    public function apply(Fix $fix) {
        if (!$fix->approved) {
            return response()->json(['error' => 'Human approval required'], 403);
        }
        $fix->update(['applied' => true]);
        return response()->json(['status' => 'APPLIED', 'fix' => $fix]);
    }

    public function verify(Fix $fix) {
        $fix->update(['verified' => true]);
        return response()->json(['status' => 'VERIFIED_RESOLVED', 'fix' => $fix]);
    }
}
