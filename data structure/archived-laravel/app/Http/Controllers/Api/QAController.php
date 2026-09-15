<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Project;

class QAController extends Controller {
    public function createPlan(Request $request, Project $project) {
        return response()->json(['plan_id' => 'qa-plan-1', 'status' => 'GENERATED']);
    }
    public function executeRun(Request $request) {
        return response()->json(['status' => 'PASS', 'passed' => 3, 'failed' => 0]);
    }
}
