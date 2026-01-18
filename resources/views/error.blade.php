@php($message = session('easyauth_error') ?? request('message'))

<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Sign in failed</title>
    </head>
    <body>
        <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px;">
            <div style="max-width: 520px; width: 100%; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, 'Apple Color Emoji', 'Segoe UI Emoji';">
                <h1 style="font-size: 20px; font-weight: 600; margin: 0 0 8px;">Sign in failed</h1>
                <p style="margin: 0 0 16px; color: #4b5563;">
                    {{ $message ?: 'We could not complete the sign in. Please try again.' }}
                </p>
                <a
                    href="{{ route('sso.login') }}"
                    style="display: inline-block; background: #D45500; color: white; padding: 10px 14px; border-radius: 10px; text-decoration: none; font-weight: 600;"
                >
                    Try again
                </a>
            </div>
        </div>
    </body>
</html>
