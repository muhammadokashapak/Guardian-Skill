<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class OrderController extends Controller {
    public function show(Request $request, $id) {
        // VULNERABILITY: Direct DB raw query without parameter binding
        $order = DB::select("SELECT * FROM orders WHERE id = " . $id);
        return response()->json($order);
    }
    
    public function update(Request $request, $id) {
        // VULNERABILITY: Missing authorization check / mass assignment
        $order = DB::table('orders')->where('id', $id)->update($request->all());
        return response()->json(['status' => 'updated']);
    }
}
