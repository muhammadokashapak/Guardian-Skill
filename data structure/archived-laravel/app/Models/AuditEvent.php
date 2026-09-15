<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class AuditEvent extends Model {
    use HasUuids;
    protected $fillable = [
        'organization_id', 'project_id', 'actor_type', 'actor_id', 'event_type',
        'target_type', 'target_id', 'action_class', 'policy_decision', 'risk_level',
        'metadata_json', 'prev_hash', 'hash'
    ];
    protected $casts = ['metadata_json' => 'array'];
}
