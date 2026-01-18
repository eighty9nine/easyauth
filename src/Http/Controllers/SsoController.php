<?php

namespace EightyNine\EasyAuth\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Symfony\Component\HttpKernel\Exception\HttpException;

class SsoController
{
    public function redirect(Request $request): RedirectResponse
    {
        $returnTo = $this->sanitizeReturnTo($request->query('return_to'));

        if ($returnTo) {
            $request->session()->put('url.intended', $returnTo);
        }

        $base = rtrim(config('easyauth.auth_server_url'), '/');
        $redirectUri = $this->resolveRedirectUri();
        $scopes = config('easyauth.scopes');
        $state = Str::random(40);
        $usePkce = (bool) config('easyauth.use_pkce', true);
        $codeVerifier = $usePkce ? Str::random(80) : null;

        $request->session()->put('easyauth_state', $state);
        $request->session()->put('easyauth_redirect_uri', $redirectUri);

        if ($usePkce && $codeVerifier) {
            $request->session()->put('easyauth_code_verifier', $codeVerifier);
        }

        $query = http_build_query([
            'client_id' => config('easyauth.client_id'),
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => $scopes,
            'state' => $state,
            'code_challenge' => $usePkce && $codeVerifier ? $this->codeChallenge($codeVerifier) : null,
            'code_challenge_method' => $usePkce ? 'S256' : null,
        ]);

        return redirect()->away("{$base}/oauth/authorize?{$query}");
    }

    public function callback(Request $request): RedirectResponse
    {
        $expectedState = $request->session()->pull('easyauth_state');
        $codeVerifier = $request->session()->pull('easyauth_code_verifier');
        $redirectUri = $request->session()->pull('easyauth_redirect_uri') ?? $this->resolveRedirectUri();
        $state = $request->string('state')->toString();
        $code = $request->string('code')->toString();

        $oauthError = $request->string('error')->toString();
        $oauthErrorDescription = $request->string('error_description')->toString();
        $oauthErrorHint = $request->string('hint')->toString();

        if ($oauthError !== '') {
            info('[Error] '.$oauthError.': '.$oauthErrorDescription.' - Hint: '.$oauthErrorHint);

            $message = $oauthErrorDescription !== '' ? $oauthErrorDescription : 'Authentication was cancelled or failed.';

            if ($oauthErrorHint !== '') {
                $message .= " (Hint: {$oauthErrorHint})";
            }

            return $this->errorResponse($request, $message);
        }

        if (! $expectedState || $state !== $expectedState) {
            return $this->errorResponse($request, 'Your session expired. Please try again.');
        }

        if ($code === '') {
            return $this->errorResponse($request, 'Authorization code missing. Please try again.');
        }

        $base = rtrim(config('easyauth.auth_server_url'), '/');

        $tokenResponse = Http::asForm()->post("{$base}/oauth/token", [
            'grant_type' => 'authorization_code',
            'client_id' => config('easyauth.client_id'),
            'client_secret' => config('easyauth.client_secret'),
            'redirect_uri' => $redirectUri,
            'code' => $code,
            'code_verifier' => $codeVerifier,
        ]);

        if (! $tokenResponse->successful()) {
            return $this->errorResponse($request, $this->extractOAuthError($tokenResponse, 'Token exchange failed.'));
        }

        $payload = $tokenResponse->json();
        $accessToken = $payload['access_token'] ?? null;

        if (! $accessToken) {
            return $this->errorResponse($request, 'Access token missing.');
        }

        $this->storeTokens($request, $payload);

        $userinfoEndpoint = config('easyauth.userinfo_endpoint', '/api/oauth/userinfo');
        $userinfoUrl = Str::startsWith($userinfoEndpoint, 'http')
            ? $userinfoEndpoint
            : $base.$userinfoEndpoint;

        $userinfoResponse = Http::withToken($accessToken)->get($userinfoUrl);

        if (! $userinfoResponse->successful()) {
            return $this->errorResponse($request, 'Failed to load user profile.');
        }

        $userinfo = $userinfoResponse->json();

        try {
            $user = $this->resolveUser($userinfo);
            Auth::guard(config('easyauth.guard', 'web'))->login($user);
        } catch (HttpException $e) {
            return $this->errorResponse($request, $e->getMessage());
        }

        return redirect()->intended(config('easyauth.post_login_redirect', '/'));
    }

    private function resolveRedirectUri(): string
    {
        $configured = config('easyauth.redirect_uri');

        if (is_string($configured) && $configured !== '') {
            if (Str::startsWith($configured, 'http')) {
                return $configured;
            }

            if (Str::startsWith($configured, '/')) {
                return url($configured);
            }
        }

        return route('sso.callback');
    }

    public function refresh(Request $request): JsonResponse
    {
        $tokens = $this->getTokens($request);
        $refreshToken = $tokens['refresh_token'] ?? null;

        if (! $refreshToken) {
            return response()->json(['message' => 'Refresh token missing.'], 422);
        }

        $base = rtrim(config('easyauth.auth_server_url'), '/');

        $tokenResponse = Http::asForm()->post("{$base}/oauth/token", [
            'grant_type' => 'refresh_token',
            'client_id' => config('easyauth.client_id'),
            'client_secret' => config('easyauth.client_secret'),
            'refresh_token' => $refreshToken,
        ]);

        if (! $tokenResponse->successful()) {
            return response()->json(['message' => 'Token refresh failed.'], 401);
        }

        $payload = $tokenResponse->json();
        $this->storeTokens($request, $payload);

        return response()->json(['status' => 'refreshed']);
    }

    public function logout(Request $request): RedirectResponse
    {
        $base = rtrim(config('easyauth.auth_server_url'), '/');
        $redirect = $this->resolvePostLogoutRedirect($request);

        Auth::guard(config('easyauth.guard', 'web'))->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->away("{$base}/oauth/logout?redirect=".urlencode($redirect));
    }

    private function resolvePostLogoutRedirect(Request $request): string
    {
        $configured = config('easyauth.post_logout_redirect');

        if (is_string($configured) && $configured !== '') {
            if (Str::startsWith($configured, 'http')) {
                return $configured;
            }

            if (Str::startsWith($configured, '/')) {
                return url($configured);
            }
        }

        $returnTo = $this->sanitizeReturnTo($request->headers->get('referer'));

        return $returnTo
            ? route('sso.login', ['return_to' => $returnTo])
            : route('sso.login');
    }

    private function sanitizeReturnTo(mixed $value): ?string
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        $value = trim($value);

        if ($value === '') {
            return null;
        }

        $appUrl = url('/');
        $appHost = parse_url($appUrl, PHP_URL_HOST);

        if (Str::startsWith($value, '/')) {
            if (Str::startsWith($value, '//')) {
                return null;
            }

            $absolute = url($value);
            $absoluteHost = parse_url($absolute, PHP_URL_HOST);

            return ($absoluteHost && $absoluteHost === $appHost) ? $absolute : null;
        }

        if (! Str::startsWith($value, 'http')) {
            return null;
        }

        $host = parse_url($value, PHP_URL_HOST);

        if (! $host || $host !== $appHost) {
            return null;
        }

        // Avoid redirecting back into the SSO endpoints.
        $path = (string) (parse_url($value, PHP_URL_PATH) ?? '');
        $prefix = '/'.trim((string) config('easyauth.route_prefix', 'auth'), '/');

        if (Str::startsWith($path, $prefix)) {
            return null;
        }

        return $value;
    }

    public function error(Request $request): View
    {
        return view('easyauth::error');
    }

    /**
     * @param  array<string, mixed>  $userinfo
     */
    private function resolveUser(array $userinfo): Authenticatable
    {
        $modelClass = config('easyauth.user_model');
        $identifierKey = config('easyauth.user_identifier', 'email');
        $emailKey = config('easyauth.email_attribute', 'email');
        $nameKey = config('easyauth.name_attribute', 'name');
        $identifierValue = $userinfo[$identifierKey]
            ?? $userinfo[$emailKey]
            ?? $userinfo['sub']
            ?? null;

        if (! $identifierValue) {
            throw new HttpException(422, 'Unable to resolve user identity.');
        }

        $model = new $modelClass;
        $table = $model->getTable();

        $user = $modelClass::query()->where($identifierKey, $identifierValue)->first();

        if (! $user) {
            $attributes = [
                $identifierKey => $identifierValue,
            ];

            if (Schema::hasColumn($table, $emailKey) && isset($userinfo[$emailKey])) {
                $attributes[$emailKey] = $userinfo[$emailKey];
            }

            if (Schema::hasColumn($table, $nameKey) && isset($userinfo[$nameKey])) {
                $attributes[$nameKey] = $userinfo[$nameKey];
            }

            if (Schema::hasColumn($table, 'password')) {
                $attributes['password'] = Hash::make(Str::random(40));
            }

            $user = $modelClass::query()->create($attributes);
        }

        return $user;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function storeTokens(Request $request, array $payload): void
    {
        $expiresIn = (int) ($payload['expires_in'] ?? 0);
        $expiresAt = $expiresIn > 0 ? now()->addSeconds($expiresIn) : null;

        $tokens = [
            'access_token' => $payload['access_token'] ?? null,
            'refresh_token' => $payload['refresh_token'] ?? null,
            'id_token' => $payload['id_token'] ?? null,
            'expires_in' => $expiresIn,
            'expires_at' => $expiresAt?->toIso8601String(),
        ];

        $request->session()->put('easyauth_tokens', $tokens);

        if (config('easyauth.token_store') === 'cache') {
            $key = $this->cacheKey($request);
            Cache::put($key, $tokens, $expiresIn > 0 ? $expiresIn : 3600);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function getTokens(Request $request): array
    {
        if (config('easyauth.token_store') === 'cache') {
            $key = $this->cacheKey($request);
            $cached = Cache::get($key);

            if (is_array($cached)) {
                return $cached;
            }
        }

        return $request->session()->get('easyauth_tokens', []);
    }

    private function cacheKey(Request $request): string
    {
        $sessionId = $request->session()->getId();

        return sprintf('%s:%s', config('easyauth.cache_prefix', 'easyauth_tokens'), $sessionId);
    }

    private function codeChallenge(string $verifier): string
    {
        return $this->base64UrlEncode(hash('sha256', $verifier, true));
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function errorResponse(Request $request, string $message): RedirectResponse
    {
        $message = Str::limit(trim($message), 300, '…');

        return redirect()
            ->route('sso.error', ['message' => $message])
            ->with('easyauth_error', $message);
    }

    private function extractOAuthError(\Illuminate\Http\Client\Response $response, string $fallback): string
    {
        $payload = $response->json();

        if (! is_array($payload)) {
            return $fallback;
        }

        $description = (string) ($payload['error_description'] ?? '');
        $error = (string) ($payload['error'] ?? '');
        $hint = (string) ($payload['hint'] ?? '');

        $message = $description !== '' ? $description : $fallback;

        if (($hint !== '') && ! str_contains($message, 'Hint:')) {
            $message .= " (Hint: {$hint})";
        }

        if (($error !== '') && ! str_contains($message, $error)) {
            $message = "{$error}: {$message}";
        }

        return $message;
    }
}
