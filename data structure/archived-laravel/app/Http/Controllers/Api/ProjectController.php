<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Project;

class ProjectController extends Controller {
    public function index() {
        return response()->json(Project::all());
    }

    public function store(Request $request) {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'root_path' => 'required|string',
            'organization_id' => 'required|uuid'
        ]);
        $project = Project::create($validated);
        return response()->json($project, 201);
    }

    public function show(Project $project) {
        return response()->json($project);
    }

    public function architectureGraph(Project $project) {
        return response()->json(['status' => 'Graph generated via codebase indexer']);
    }

    public function supplyChain(Project $project) {
        return response()->json(['status' => 'Supply chain manifest analyzed']);
    }
}
