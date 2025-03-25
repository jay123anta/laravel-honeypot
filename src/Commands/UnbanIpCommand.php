<?php namespace Security\Honeypot\Commands; use Illuminate\Console\Command; class UnbanIpCommand extends Command { protected $signature = 'honeypot:unban-ip {ip}'; protected $description = 'Unban IP via iptables'; public function handle() { $ip = $this->argument('ip'); exec("iptables -D INPUT -s {$ip} -j DROP"); $this->info("IP {$ip} unbanned."); } }