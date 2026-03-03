<?php

namespace JayAnta\ThreatDetection\Notifications;

use Illuminate\Notifications\Notification;

class ThreatAlertSlack extends Notification
{
    protected array $log;

    public function __construct(array $log)
    {
        $this->log = $log;
    }

    public function via($notifiable): array
    {
        return ['slack'];
    }

    /**
     * Build the Slack notification.
     *
     * Works with both:
     * - Laravel 10 built-in SlackMessage (illuminate/notifications)
     * - Laravel 11+ via laravel/slack-notification-channel package
     */
    public function toSlack($notifiable)
    {
        $log = $this->log;

        // Break the URL to avoid auto-linking in Slack
        $url = $log['url'] ?? 'N/A';
        $sanitizedUrl = preg_replace('/^https?:\/\//i', 'hxxp://', $url);
        $sanitizedUrl = str_replace('.', '[.]', $sanitizedUrl);

        // Laravel 11+ uses laravel/slack-notification-channel with SlackMessage in a different namespace
        $slackMessageClass = class_exists(\Illuminate\Notifications\Messages\SlackMessage::class)
            ? \Illuminate\Notifications\Messages\SlackMessage::class
            : \Illuminate\Notifications\Slack\SlackMessage::class;

        return (new $slackMessageClass)
            ->from(config('threat-detection.notifications.slack_username', 'ThreatBot'))
            ->to(config('threat-detection.notifications.slack_channel', '#threat-alerts'))
            ->warning()
            ->content('@here *Threat Detected*')
            ->attachment(function ($attachment) use ($log, $sanitizedUrl) {
                $attachment->fields([
                    'IP'     => $log['ip_address'] ?? 'N/A',
                    'URL'    => $sanitizedUrl,
                    'Type'   => $log['type'] ?? 'Unknown',
                    'Level'  => ucfirst($log['threat_level'] ?? 'low'),
                    'Action' => $log['action_taken'] ?? 'N/A',
                ]);
            });
    }
}
