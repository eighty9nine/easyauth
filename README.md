# EasyAuth Client Plugin

This guide is for a developer who has never wired SSO before. Follow the steps exactly.

## Overview 
## Step 1: Create a client on the EasyAuth server

1. Log in to the EasyAuth admin panel.
2. Create a new OAuth client.
3. Copy the **Client ID** and **Client Secret**.
4. Add your app’s callback URL. Example:
	 - https://your-app.test/auth/callback

The callback URL is provided by this package (it’s always your `APP_URL` + the callback route). You can also print it by running `php artisan easyauth:install --publish`.

You need these values for your app’s .env in Step 4.

## Step 2: Install the plugin in your app

Run this in your Laravel/Filament app:

```bash
composer require eightynine/easyauth
php artisan easyauth:install --publish
```

This adds the routes and publishes the config file.

## Step 3: Ensure your app has sessions enabled

The plugin uses sessions to store the OAuth state, tokens, and login status. Make sure:

- Your app uses the `web` middleware group.
- `SESSION_DRIVER` is set (database or file both work).

## Step 4: Add the EasyAuth settings to your .env

Use the values from Step 1:

```dotenv
EASYAUTH_SERVER_URL=https://auth.example.com
EASYAUTH_CLIENT_ID=your-client-id
EASYAUTH_CLIENT_SECRET=your-client-secret
```

Everything else can be configured in `config/easyauth.php` (published in Step 2).

## Step 5: Send users to /auth/login

This route is provided by the plugin. Example:

- Add a “Sign in with EasyAuth” button that links to `/auth/login`.

When a user visits `/auth/login`, the plugin redirects them to:

- https://auth.example.com/oauth/authorize?client_id=...&redirect_uri=...

### Optional: use the built-in "Continue with Easy Auth" button

The plugin provides a Blade component you can drop into any Blade view:

```blade
<x-continue-with-easyauth />
```

This renders a branded button linking to `route('sso.login')`.

### Optional: override your app's login route

If you want `/login` (or other paths) to redirect into the EasyAuth flow, enable route overrides in `config/easyauth.php`:

```php
'route_overrides' => [
	'enabled' => true,
	'login_paths' => ['/login'],
],
```

## Step 6: What happens on callback (automatic)

After login, EasyAuth redirects back to your callback URL with a code.

The plugin does this automatically:

1. Exchanges the code for tokens at `/oauth/token`.
2. Calls `/api/oauth/userinfo` to fetch the user profile.
3. Finds or creates a local user.
4. Logs the user into your app.
5. Redirects to the intended URL, falling back to `easyauth.post_login_redirect`.

You do not need to write this logic yourself.

## Step 7: Logout

POST `/auth/logout` to:

1. Log out locally.
2. Redirect the user to EasyAuth logout.

## Routes provided by the plugin

- /auth/login: start SSO
- /auth/callback: complete SSO (implemented by the plugin)
- /auth/refresh: refresh tokens
- /auth/logout: log out
- /auth/error: error screen

## User mapping (when the user does not exist locally)

The plugin creates a local user using:

- `EASYAUTH_USER_IDENTIFIER` (default: email)
- `EASYAUTH_NAME_ATTRIBUTE` (default: name)
- `EASYAUTH_EMAIL_ATTRIBUTE` (default: email)

If your users are matched by another field, set those keys in .env.

## Common issues and fixes

- Redirect URI mismatch: the callback URL must exactly match what you registered.
- Invalid state: user opened the callback in a different browser or session expired.
- Userinfo failed: make sure the userinfo endpoint is reachable and scopes include `openid`.
