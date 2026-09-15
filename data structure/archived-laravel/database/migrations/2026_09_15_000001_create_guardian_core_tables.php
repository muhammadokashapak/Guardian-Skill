<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('organizations', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('name');
            $table->string('slug')->unique();
            $table->timestamps();
        });

        Schema::create('projects', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('organization_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('root_path');
            $table->string('repository_type')->default('git');
            $table->string('default_branch')->default('main');
            $table->string('risk_profile')->default('MEDIUM');
            $table->string('status')->default('ACTIVE');
            $table->timestamps();
            $table->index(['organization_id', 'status']);
        });

        Schema::create('project_snapshots', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('project_id')->constrained()->cascadeOnDelete();
            $table->string('commit_hash')->nullable();
            $table->string('tree_hash');
            $table->integer('file_count')->default(0);
            $table->timestamps();
        });

        Schema::create('scans', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('project_id')->constrained()->cascadeOnDelete();
            $table->uuid('snapshot_id')->nullable();
            $table->string('scan_type')->default('FULL');
            $table->string('status')->default('QUEUED');
            $table->string('engine_version')->default('1.0.0');
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->timestamps();
            $table->index(['project_id', 'status']);
        });

        Schema::create('findings', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('scan_id')->constrained()->cascadeOnDelete();
            $table->foreignUuid('project_id')->constrained()->cascadeOnDelete();
            $table->string('fingerprint', 64)->index();
            $table->string('category');
            $table->string('severity');
            $table->float('confidence')->default(1.0);
            $table->string('status')->default('OPEN');
            $table->string('title');
            $table->text('summary');
            $table->string('affected_path');
            $table->integer('line_start')->nullable();
            $table->integer('line_end')->nullable();
            $table->text('root_cause')->nullable();
            $table->text('impact')->nullable();
            $table->text('remediation')->nullable();
            $table->string('source_tool')->default('guardian-scanner');
            $table->timestamps();
            $table->index(['project_id', 'fingerprint']);
            $table->index(['project_id', 'severity']);
        });

        Schema::create('finding_evidence', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('finding_id')->constrained()->cascadeOnDelete();
            $table->string('evidence_type');
            $table->text('data');
            $table->string('file_path')->nullable();
            $table->integer('line_start')->nullable();
            $table->integer('line_end')->nullable();
            $table->timestamps();
        });

        Schema::create('fixes', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('finding_id')->constrained()->cascadeOnDelete();
            $table->foreignUuid('project_id')->constrained()->cascadeOnDelete();
            $table->string('title');
            $table->text('explanation');
            $table->longText('diff');
            $table->json('target_files');
            $table->string('risk_level');
            $table->boolean('requires_approval')->default(true);
            $table->boolean('approved')->default(false);
            $table->boolean('applied')->default(false);
            $table->boolean('verified')->default(false);
            $table->timestamps();
        });

        Schema::create('approvals', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('fix_id')->constrained()->cascadeOnDelete();
            $table->string('requested_by');
            $table->string('approved_by')->nullable();
            $table->string('risk_level');
            $table->string('decision')->default('PENDING');
            $table->text('reason')->nullable();
            $table->timestamps();
        });

        Schema::create('audit_events', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('organization_id')->index();
            $table->string('project_id')->nullable()->index();
            $table->string('actor_type')->default('SYSTEM');
            $table->string('actor_id')->default('guardian');
            $table->string('event_type')->index();
            $table->string('target_type');
            $table->string('target_id');
            $table->string('action_class');
            $table->string('policy_decision');
            $table->string('risk_level')->default('LOW');
            $table->json('metadata_json');
            $table->string('prev_hash', 64);
            $table->string('hash', 64);
            $table->timestamps();
        });
    }

    public function down(): void {
        Schema::dropIfExists('audit_events');
        Schema::dropIfExists('approvals');
        Schema::dropIfExists('fixes');
        Schema::dropIfExists('finding_evidence');
        Schema::dropIfExists('findings');
        Schema::dropIfExists('scans');
        Schema::dropIfExists('project_snapshots');
        Schema::dropIfExists('projects');
        Schema::dropIfExists('organizations');
    }
};
