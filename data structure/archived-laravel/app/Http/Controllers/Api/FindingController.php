<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Models\Finding;

class FindingController extends Controller {
    public function index(Project $project) {
        return response()->json($project->findings()->with('evidence')->get());
    }

    public function show(Finding $finding) {
        return response()->json($finding->load('evidence', 'fixes'));
    }
}
