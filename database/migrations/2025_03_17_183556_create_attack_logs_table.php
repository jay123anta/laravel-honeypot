<?php 

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
        Schema::connection('honeypot')->create('attack_logs', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address');
            $table->text('user_agent');
            $table->text('url');
            $table->json('payload');
            $table->string('type');
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::connection('honeypot')->dropIfExists('attack_logs');
    }
};