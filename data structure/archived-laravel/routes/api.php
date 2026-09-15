<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\ProjectController;
use App\Http\Controllers\Api\ScanController;
use App\Http\Controllers\Api\FindingController;
use App\Http\Controllers\Api\FixController;
use App\Http\Controllers\Api\IncidentController;
use App\Http\Controllers\Api\QAController;
use App\Http\Controllers\Api\ChangeImpactController;
use App\Http\Controllers\Api\AuditController;
use App\Http\Controllers\Api\SelfAuditController;

Route::prefix('v1')->group(function () {
    // System & Health
    Route::get('/system-health', [SelfAuditController::class, 'health']);
    Route::post('/self-audit', [SelfAuditController::class, 'selfAudit']);
    Route::get('/audit-events', [AuditController::class, 'index']);

    // Projects & Discovery
    Route::get('/projects', [ProjectController::class, 'index']);
    Route::post('/projects', [ProjectController::class, 'store']);
    Route::get('/projects/{project}', [ProjectController::class, 'show']);
    Route::get('/projects/{project}/architecture-graph', [ProjectController::class, 'architectureGraph']);
    Route::get('/projects/{project}/supply-chain', [ProjectController::class, 'supplyChain']);

    // Scans & Findings
    Route::post('/projects/{project}/scans', [ScanController::class, 'store']);
    Route::get('/scans/{scan}', [ScanController::class, 'show']);
    Route::get('/projects/{project}/findings', [FindingController::class, 'index']);
    Route::get('/findings/{finding}', [FindingController::class, 'show']);

    // Fix Engine & Approvals
    Route::post('/findings/{finding}/fix-plan', [FixController::class, 'createPlan']);
    Route::post('/fixes/{fix}/approve', [FixController::class, 'approve']);
    Route::post('/fixes/{fix}/apply', [FixController::class, 'apply']);
    Route::post('/fixes/{fix}/verify', [FixController::class, 'verify']);

    // Engineering Intelligence
    Route::post('/projects/{project}/impact-analysis', [ChangeImpactController::class, 'analyze']);
    Route::post('/projects/{project}/incidents', [IncidentController::class, 'store']);
    Route::post('/incidents/{incident}/investigate', [IncidentController::class, 'investigate']);
    Route::post('/projects/{project}/qa/plans', [QAController::class, 'createPlan']);
    Route::post('/qa/runs', [QAController::class, 'executeRun']);
});
