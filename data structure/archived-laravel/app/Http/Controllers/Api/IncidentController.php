<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Project;

class IncidentController extends Controller {
    public function store(Request $request, Project $project) {
        return response()->json(['incident_id' => 'inc-1', 'title' => $request->input('title')]);
    }
    public function investigate(Request $request, $id) {
        return response()->json(['probable_root_cause' => 'Null pointer in auth pipeline', 'confidence' => 0.88]);
    }
}
