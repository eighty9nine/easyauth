<?php

namespace EightyNine\EasyAuth;

use EightyNine\EasyAuth\Console\InstallEasyAuthCommand;
use EightyNine\EasyAuth\Http\Controllers\SsoController;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class EasyAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/easyauth.php', 'easyauth');
    }

    public function boot(): void
    {
        $this->app->booted(function (): void {
            $this->registerRoutes();
        });
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'easyauth');

        Blade::component('easyauth::components.continue-with-easyauth', 'continue-with-easyauth');

        $this->publishes([
            __DIR__.'/../config/easyauth.php' => config_path('easyauth.php'),
        ], 'easyauth-config');

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/easyauth'),
        ], 'easyauth-views');

        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallEasyAuthCommand::class,
            ]);
        }
    }

    private function registerRoutes(): void
    {
        if ($this->app->routesAreCached()) {
            return;
        }

        Route::middleware('web')->group(function (): void {
            $prefix = trim((string) config('easyauth.route_prefix', 'auth'), '/');

            Route::prefix($prefix)->group(function (): void {
                Route::get('/login', [SsoController::class, 'redirect'])->name('sso.login');
                Route::get('/callback', [SsoController::class, 'callback'])->name('sso.callback');
                Route::get('/error', [SsoController::class, 'error'])->name('sso.error');
                Route::post('/refresh', [SsoController::class, 'refresh'])->name('sso.refresh');
                Route::post('/logout', [SsoController::class, 'logout'])->name('sso.logout');
            });

            if (config('easyauth.route_overrides.enabled', false)) {
                $loginPaths = (array) config('easyauth.route_overrides.login_paths', ['/login']);
                $registerPaths = (array) config('easyauth.route_overrides.register_paths', ['/register']);
                $passwordPaths = (array) config('easyauth.route_overrides.password_paths', []);

                $filamentLoginRouteName = $this->resolveFilamentLoginRouteName();
                $filamentLogoutRouteName = $this->resolveFilamentLogoutRouteName();
                $primaryLoginPath = $this->firstValidPath($loginPaths);
                $primaryRegisterPath = $this->firstValidPath($registerPaths);

                if ($filamentLoginRouteName && $primaryLoginPath) {
                    Route::get($primaryLoginPath, fn () => redirect()->route('sso.login'))
                        ->name($filamentLoginRouteName);
                }

                foreach ($loginPaths as $path) {
                    if (! is_string($path) || $path === '') {
                        continue;
                    }

                    if ($primaryLoginPath && $path === $primaryLoginPath && $filamentLoginRouteName) {
                        continue;
                    }

                    Route::get($path, fn () => redirect()->route('sso.login'));
                }

                if ($primaryRegisterPath) {
                    Route::match(['GET', 'POST'], $primaryRegisterPath, fn () => redirect()->route('sso.login'))
                        ->name('register');
                }

                foreach ($registerPaths as $path) {
                    if (! is_string($path) || $path === '') {
                        continue;
                    }

                    if ($primaryRegisterPath && $path === $primaryRegisterPath) {
                        continue;
                    }

                    Route::match(['GET', 'POST'], $path, fn () => redirect()->route('sso.login'));
                }

                if ($this->hasAnyString($passwordPaths)) {
                    // Guest routes
                    Route::get('/forgot-password', fn () => redirect()->route('sso.login'))
                        ->name('password.request');
                    Route::post('/forgot-password', fn () => redirect()->route('sso.login'))
                        ->name('password.email');
                    Route::get('/reset-password/{token}', fn () => redirect()->route('sso.login'))
                        ->name('password.reset');
                    Route::post('/reset-password', fn () => redirect()->route('sso.login'))
                        ->name('password.store');

                    // Auth routes (email verification / password confirm / update)
                    Route::get('/verify-email', fn () => redirect()->route('sso.login'))
                        ->name('verification.notice');
                    Route::get('/verify-email/{id}/{hash}', fn () => redirect()->route('sso.login'))
                        ->name('verification.verify');
                    Route::post('/email/verification-notification', fn () => redirect()->route('sso.login'))
                        ->name('verification.send');
                    Route::get('/confirm-password', fn () => redirect()->route('sso.login'))
                        ->name('password.confirm');
                    Route::post('/confirm-password', fn () => redirect()->route('sso.login'));
                    Route::put('/password', fn () => redirect()->route('sso.login'))
                        ->name('password.update');

                    // Additional/custom endpoints
                    foreach ($passwordPaths as $path) {
                        if (! is_string($path) || $path === '') {
                            continue;
                        }

                        Route::match(['GET', 'POST', 'PUT'], $path, fn () => redirect()->route('sso.login'));
                    }
                }

                $logoutPath = config('easyauth.route_overrides.logout_path') ?? '/logout';

                if (is_string($logoutPath) && $logoutPath !== '') {
                    $route = Route::post($logoutPath, [SsoController::class, 'logout']);

                    if ($filamentLogoutRouteName) {
                        $route->name($filamentLogoutRouteName);
                    }
                }
            }
        });
    }

    private function resolveFilamentLoginRouteName(): ?string
    {
        if (! class_exists(\Filament\Facades\Filament::class)) {
            return null;
        }

        try {
            $panel = \Filament\Facades\Filament::getCurrentOrDefaultPanel();

            if (! $panel) {
                return null;
            }

            return $panel->generateRouteName('auth.login');
        } catch (\Throwable) {
            return null;
        }
    }

    private function resolveFilamentLogoutRouteName(): ?string
    {
        if (! class_exists(\Filament\Facades\Filament::class)) {
            return null;
        }

        try {
            $panel = \Filament\Facades\Filament::getCurrentOrDefaultPanel();

            if (! $panel) {
                return null;
            }

            return $panel->generateRouteName('auth.logout');
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @param  array<array-key, mixed>  $paths
     */
    private function firstValidPath(array $paths): ?string
    {
        foreach ($paths as $path) {
            if (! is_string($path) || $path === '') {
                continue;
            }

            return $path;
        }

        return null;
    }

    /**
     * @param  array<array-key, mixed>  $values
     */
    private function hasAnyString(array $values): bool
    {
        foreach ($values as $value) {
            if (is_string($value) && $value !== '') {
                return true;
            }
        }

        return false;
    }
}
