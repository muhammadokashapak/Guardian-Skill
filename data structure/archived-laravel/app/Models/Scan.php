<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class Scan extends Model {
    use HasUuids;
    protected $fillable = ['project_id', 'snapshot_id', 'scan_type', 'status', 'engine_version', 'started_at', 'finished_at'];
    public function findings() { return $this->hasMany(Finding::class); }
}
