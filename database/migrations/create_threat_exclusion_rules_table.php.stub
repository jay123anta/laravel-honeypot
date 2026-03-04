<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('threat_exclusion_rules', function (Blueprint $table) {
            $table->id();
            $table->string('pattern_label');
            $table->string('path_pattern')->nullable();
            $table->string('source_context')->nullable();
            $table->unsignedBigInteger('created_from_threat_id')->nullable();
            $table->unsignedBigInteger('created_by_user_id')->nullable();
            $table->text('reason')->nullable();
            $table->boolean('is_active')->default(true)->index();
            $table->timestamps();

            $table->index(['pattern_label', 'path_pattern']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('threat_exclusion_rules');
    }
};
