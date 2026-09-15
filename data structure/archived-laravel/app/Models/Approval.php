<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class Approval extends Model {
    use HasUuids;
    protected $fillable = ['fix_id', 'requested_by', 'approved_by', 'risk_level', 'decision', 'reason'];
}
