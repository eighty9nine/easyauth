<?php

namespace EightyNine\EasyAuth\Console;

use Illuminate\Console\Command;

class InstallEasyAuthCommand extends Command
{
    protected $signature = 'easyauth:install {--publish : Publish the EasyAuth config file}';

    protected $description = 'Install and configure EasyAuth client settings.';

    public function handle(): int
    {
        if ($this->option('publish')) {
            $this->call('vendor:publish', [
                '--tag' => 'easyauth-config',
                '--force' => true,
            ]);
        }

        $this->line('Add these environment variables to your .env:');
        $this->line('EASYAUTH_SERVER_URL=https://auth.example.com');
        $this->line('EASYAUTH_CLIENT_ID=');
        $this->line('EASYAUTH_CLIENT_SECRET=');
        $this->line('');
        $this->line('Register this callback URL on the EasyAuth server:');
        $this->line(route('sso.callback'));
        $this->line('');
        $this->line('All other settings live in config/easyauth.php after publishing.');

        return self::SUCCESS;
    }
}
