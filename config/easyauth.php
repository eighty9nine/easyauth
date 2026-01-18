<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Core OAuth settings (recommended via .env)
    |--------------------------------------------------------------------------
    |
    | Keep environment variables minimal. In most apps, these 3 are all you need
    | in `.env`, and everything else can live here.
    */

    // Base URL of your EasyAuth server (no trailing slash required).
    'auth_server_url' => env('EASYAUTH_SERVER_URL', 'https://auth.example.com'),

    // OAuth client credentials created on the EasyAuth server.
    'client_id' => env('EASYAUTH_CLIENT_ID'),
    'client_secret' => env('EASYAUTH_CLIENT_SECRET'),

    // Your application's callback URL.
    // If set to `null`, the package will resolve it from the callback route
    // (e.g. APP_URL + '/auth/callback').
    'redirect_uri' => null,

    // Space-delimited OAuth scopes.
    // If your auth server is not OpenID Connect (OIDC), do not include `openid`.
    'scopes' => '*',

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    */

    // The prefix for the plugin routes (login/callback/refresh/logout/error).
    // Default routes are:
    // - GET  /auth/login
    // - GET  /auth/callback
    // - POST /auth/refresh
    // - POST /auth/logout
    // - GET  /auth/error
    'route_prefix' => 'auth',

    // Optional route overrides (disabled by default).
    // When enabled, visiting `/login` can redirect users to the EasyAuth login
    // flow (useful if you want to "take over" a traditional login URL).
    'route_overrides' => [
        'enabled' => false,

        // One or more GET paths that should redirect to the SSO login route.
        // Example: ['/login', '/sign-in']
        'login_paths' => ['/login'],

        // One or more paths that should redirect to the SSO login route.
        // Useful if you want to disable local registration completely.
        // Both GET and POST will be redirected.
        // Example: ['/register', '/sign-up']
        'register_paths' => ['/register'],

        // Redirect password-reset and email-verification pages into SSO.
        // These are the common Laravel auth endpoints.
        // Note: For parameterized routes, include the `{...}` placeholders.
        // Example: ['forgot-password', 'reset-password/{token}', ...]
        'password_paths' => [
            '/forgot-password',
            '/reset-password/{token}',
            '/reset-password',
            '/verify-email',
            '/verify-email/{id}/{hash}',
            '/email/verification-notification',
            '/confirm-password',
            '/password',
        ],

        // Optional POST path to proxy to the SSO logout route.
        // Example: '/logout'
        'logout_path' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Post-login behavior
    |--------------------------------------------------------------------------
    */

    // Which guard to log the user into.
    'guard' => 'web',

    // Where to send the user after a successful SSO login.
    // `redirect()->intended()` will respect intended URLs first.
    'post_login_redirect' => '/',

    // Where the EasyAuth server should redirect back to after logout.
    // Defaults to the EasyAuth login route, so the user is taken back to SSO.
    // You may set an absolute URL or a path like '/login'.
    'post_logout_redirect' => null,

    /*
    |--------------------------------------------------------------------------
    | User profile mapping
    |--------------------------------------------------------------------------
    */

    // Endpoint on the EasyAuth server that returns the authenticated user profile.
    // Can be a full URL or a path relative to `auth_server_url`.
    'userinfo_endpoint' => '/api/oauth/userinfo',

    // The Eloquent model used for local users.
    'user_model' => App\Models\User::class,

    // Field used to look up existing users locally.
    // If the user doesn't exist, a new record will be created.
    'user_identifier' => 'email',

    // Which keys in the userinfo payload map to name/email columns.
    'name_attribute' => 'name',
    'email_attribute' => 'email',

    /*
    |--------------------------------------------------------------------------
    | Security & token storage
    |--------------------------------------------------------------------------
    */

    // Whether to use PKCE during the authorization code flow.
    'use_pkce' => true,

    // Where tokens are stored. Supported: 'session' or 'cache'.
    'token_store' => 'session',

    // Cache key prefix when token_store='cache'.
    'cache_prefix' => 'easyauth_tokens',

    // Seconds of tolerance when considering token expiration.
    'refresh_leeway' => 120,
];
