<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class Project extends Model {
    use HasUuids;
    protected $fillable = ['organization_id', 'name', 'root_path', 'repository_type', 'default_branch', 'risk_profile', 'status'];
    public function scans() { return $this->hasMany(Scan::class); }
    public function findings() { return $this->hasMany(Finding::class); }
}
