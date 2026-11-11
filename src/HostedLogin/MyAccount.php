<?php

namespace Touchque\HostedLogin;

/**
 * The Touchque Login My Account API (/me/v1) from your server: the signed-in
 * customer's own profile, sign-in methods, devices, apps and data, called
 * with their access token for audience https://<domain>/me/.
 *
 *   $me = $login->myAccountToken($_SESSION['refreshToken'], 'read:me update:me');  // keep $me['refreshToken']
 *   $account = $login->myAccount($me['accessToken']);
 *   $account->get()['profile'];
 *
 * Security changes, the data export and deletion need a recent sign-in; when
 * it is too old a MyAccountException with isStepUp() is thrown: send the
 * person through authorizationUrl(['maxAge' => 0]) again.
 */
class MyAccount
{
    private string $issuer;
    private string $accessToken;
    /** @var callable */
    private $transport;

    /**
     * @param callable|null $transport callable(string $method, string $url, array $headers, ?string $body): array{0:int,1:string}
     */
    public function __construct(string $domain, string $accessToken, ?callable $transport = null)
    {
        if ($domain === '' || $accessToken === '') {
            throw new MyAccountException('config', 0, 'domain and accessToken are required');
        }
        $issuer = HostedLogin::issuerFor($domain);
        if ($issuer === null) {
            throw new MyAccountException('config', 0, HostedLogin::PLAINTEXT_ISSUER);
        }
        $this->issuer = $issuer;
        $this->accessToken = $accessToken;
        $this->transport = $transport ?? [HostedLogin::class, 'curlTransport'];
    }

    /** The hosted account page, optionally at 'security', 'devices' or 'privacy'. */
    public function accountPageUrl(?string $section = null): string
    {
        return $this->issuer . '/account' . ($section ? "/{$section}" : '');
    }

    /** @return array|null */
    private function call(string $method, string $path, ?array $body = null)
    {
        $headers = ['Authorization: Bearer ' . $this->accessToken, 'Accept: application/json'];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }
        [$status, $raw] = ($this->transport)($method, $this->issuer . '/me/v1' . $path, $headers, $body === null ? null : json_encode($body, JSON_UNESCAPED_UNICODE));
        if ($status === 204) {
            return null;
        }
        $d = json_decode((string) $raw, true) ?: [];
        if ($status >= 400) {
            throw new MyAccountException($d['error'] ?? "http_{$status}", $status, $d['error_description'] ?? null, isset($d['max_age']) ? (int) $d['max_age'] : null);
        }
        return $d;
    }

    private static function seg(string $v): string
    {
        return rawurlencode($v);
    }

    public function get(): array { return $this->call('GET', ''); }
    public function getProfile(): array { return $this->call('GET', '/profile'); }

    /** name, givenName, familyName, nickname, locale, userMetadata (merged; null removes a key). */
    public function updateProfile(array $changes): array { return $this->call('PATCH', '/profile', $changes); }

    public function authenticationMethods(): array { return $this->call('GET', '/authentication-methods'); }
    public function renamePasskey(string $id, string $label): void { $this->call('PATCH', '/authentication-methods/passkeys/' . self::seg($id), ['label' => $label]); }
    /** Needs a recent sign-in. */
    public function removePasskey(string $id): void { $this->call('DELETE', '/authentication-methods/passkeys/' . self::seg($id)); }
    /** Needs a recent sign-in. */
    public function unlinkTouchqueApp(): void { $this->call('DELETE', '/authentication-methods/touchque'); }
    /** Email codes as a second step. Needs a recent sign-in. */
    public function setEmailCodes(bool $enabled): array { return $this->call('PUT', '/authentication-methods/email', ['enabled' => $enabled]); }
    /** Texts a code to a new number for text-message codes. Needs a recent sign-in. */
    public function startSmsEnrollment(string $phone): array { return $this->call('POST', '/authentication-methods/sms', ['phone' => $phone]); }
    /** The code from that text: text-message codes are on. Needs a recent sign-in. */
    public function verifySmsEnrollment(string $code): array { return $this->call('POST', '/authentication-methods/sms/verify', ['code' => $code]); }
    /** Needs a recent sign-in. */
    public function removeSmsCodes(): void { $this->call('DELETE', '/authentication-methods/sms'); }
    /** Needs a recent sign-in. */
    public function unlinkIdentity(string $id): void { $this->call('DELETE', '/identities/' . self::seg($id)); }
    /** Apps stop using a linked account for the person (token vault: the identity's appAccess id); signing in with it stays. */
    public function stopAppAccess(string $id): void { $this->call('DELETE', '/app-access/' . self::seg($id)); }
    /** Sets or changes the password; other sessions end. Needs a recent sign-in. */
    public function setPassword(string $password): array { return $this->call('PUT', '/password', ['password' => $password]); }
    /** Needs a recent sign-in and another way to sign in. */
    public function removePassword(): void { $this->call('DELETE', '/password'); }
    /** A confirmation link goes to the new address. Needs a recent sign-in. */
    public function changeEmail(string $email): array { return $this->call('POST', '/email', ['email' => $email]); }
    public function sendVerificationEmail(): array { return $this->call('POST', '/email/verification'); }

    public function sessions(): array { return $this->call('GET', '/sessions'); }
    public function endSession(string $id): void { $this->call('DELETE', '/sessions/' . self::seg($id)); }
    public function endOtherSessions(): array { return $this->call('DELETE', '/sessions'); }

    public function apps(): array { return $this->call('GET', '/apps'); }
    public function revokeApp(string $clientId): array { return $this->call('DELETE', '/apps/' . self::seg($clientId)); }
    public function consents(): array { return $this->call('GET', '/consents'); }
    public function setMarketing(bool $granted): array { return $this->call('PUT', '/consents/marketing', ['granted' => $granted]); }

    /** Everything about the person (KVKK/GDPR). Needs a recent sign-in. */
    public function exportData(): array { return $this->call('GET', '/export'); }
    /** Erases the account at once. Needs delete:me and a recent sign-in. */
    public function deleteAccount(): array { return $this->call('DELETE', ''); }
}
