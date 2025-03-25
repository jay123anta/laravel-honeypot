<?php 

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
        Schema::connection('honeypot')->create('attack_logs', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address')->nullable();
            $table->string('url')->nullable();
            $table->string('type')->nullable();
            $table->text('payload')->nullable();
            $table->string('user_agent')->nullable();
            $table->string('threat_level')->default('medium');
            $table->string('action_taken')->default('logged');
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::connection('honeypot')->dropIfExists('attack_logs');
    }
};