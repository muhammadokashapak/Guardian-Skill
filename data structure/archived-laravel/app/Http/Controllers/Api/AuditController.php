<?php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\AuditEvent;

class AuditController extends Controller {
    public function index() {
        return response()->json(AuditEvent::latest()->take(50)->get());
    }
}
