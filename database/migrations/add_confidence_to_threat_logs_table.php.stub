<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table(config('threat-detection.table_name', 'threat_logs'), function (Blueprint $table) {
            $table->unsignedTinyInteger('confidence_score')->default(0)->after('threat_level')->index();
            $table->string('confidence_label', 20)->default('low')->after('confidence_score');
            $table->boolean('is_false_positive')->default(false)->after('confidence_label')->index();
        });
    }

    public function down(): void
    {
        Schema::table(config('threat-detection.table_name', 'threat_logs'), function (Blueprint $table) {
            $table->dropIndex(['confidence_score']);
            $table->dropIndex(['is_false_positive']);
            $table->dropColumn(['confidence_score', 'confidence_label', 'is_false_positive']);
        });
    }
};
