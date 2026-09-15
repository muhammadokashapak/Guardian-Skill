<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class Finding extends Model {
    use HasUuids;
    protected $fillable = [
        'scan_id', 'project_id', 'fingerprint', 'category', 'severity',
        'confidence', 'status', 'title', 'summary', 'affected_path',
        'line_start', 'line_end', 'root_cause', 'impact', 'remediation', 'source_tool'
    ];
    public function evidence() { return $this->hasMany(FindingEvidence::class); }
    public function fixes() { return $this->hasMany(Fix::class); }
}
