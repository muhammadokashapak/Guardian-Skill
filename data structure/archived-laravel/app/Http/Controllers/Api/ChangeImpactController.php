<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Project;

class ChangeImpactController extends Controller {
    public function analyze(Request $request, Project $project) {
        return response()->json([
            'affected_files' => ['app/Http/Controllers/OrderController.php'],
            'backward_compatible' => true,
            'deployment_risk' => 'LOW'
        ]);
    }
}
