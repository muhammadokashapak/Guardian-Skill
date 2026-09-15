<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class FindingEvidence extends Model {
    use HasUuids;
    protected $fillable = ['finding_id', 'evidence_type', 'data', 'file_path', 'line_start', 'line_end'];
}
