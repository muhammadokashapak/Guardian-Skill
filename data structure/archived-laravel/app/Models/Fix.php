<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class Fix extends Model {
    use HasUuids;
    protected $fillable = [
        'finding_id', 'project_id', 'title', 'explanation', 'diff',
        'target_files', 'risk_level', 'requires_approval', 'approved', 'applied', 'verified'
    ];
    protected $casts = ['target_files' => 'array', 'approved' => 'boolean', 'applied' => 'boolean', 'verified' => 'boolean'];
    public function approvals() { return $this->hasMany(Approval::class); }
}
