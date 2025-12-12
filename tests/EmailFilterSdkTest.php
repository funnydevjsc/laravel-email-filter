<?php

declare(strict_types=1);

use FunnyDev\EmailFilter\EmailFilterSdk;
use PHPUnit\Framework\TestCase;

final class EmailFilterSdkTest extends TestCase
{
    private function sdk(string $tld = '', array $credentials = []): EmailFilterSdk
    {
        // Ensure we don't trigger Config facade by passing a non-empty credentials array
        $creds = $credentials ?: ['maxmind' => ['account' => null, 'license' => null]];
        return new EmailFilterSdk($tld, $creds);
    }

    public function testInvalidEmailFormat(): void
    {
        $sdk = $this->sdk('com|net');
        $res = $sdk->validate('not-an-email', true);
        $this->assertFalse($res['recommend']);
        $this->assertSame('Invalid email format', $res['reason']);
    }

    public function testUsernamePolicyRejectsPlusSign(): void
    {
        $sdk = $this->sdk('com|net');
        $res = $sdk->validate('user+tag@example.com', true);
        $this->assertFalse($res['recommend']);
        $this->assertFalse($res['trustable']['username']);
        $this->assertSame('This email username was marked as dirty', $res['reason']);
    }

    public function testAllowedTldAcceptsValidDomainTrust(): void
    {
        $sdk = $this->sdk('com|net');
        $res = $sdk->validate('user.name-1@example.com', true);
        $this->assertTrue($res['trustable']['domain_trust']);
    }

    public function testTldNotAllowedRejectsDomain(): void
    {
        $sdk = $this->sdk('net');
        $res = $sdk->validate('user@example.com', true);
        $this->assertFalse($res['recommend']);
        $this->assertFalse($res['trustable']['domain_trust']);
        $this->assertSame('This email domain was blocked by default policy', $res['reason']);
    }

    public function testDomainWithDigitsIsRejectedByPolicy(): void
    {
        $sdk = $this->sdk('com|net');
        $res = $sdk->validate('user@examp1e.com', true);
        $this->assertFalse($res['recommend']);
        $this->assertSame('This email domain was blocked by default policy', $res['reason']);
    }

    public function testDomainWithTooManyLabelsIsRejected(): void
    {
        $sdk = $this->sdk('d');
        $res = $sdk->validate('user@a.b.c.d', true);
        $this->assertFalse($res['recommend']);
        $this->assertSame('This email domain was blocked by default policy', $res['reason']);
    }

    public function testDisposableDomainIsRejected(): void
    {
        $sdk = $this->sdk('com|net');
        $res = $sdk->validate('u@mailinator.com', true);
        $this->assertFalse($res['recommend']);
        $this->assertTrue($res['trustable']['disposable']);
        $this->assertSame('This email was marked as disposable', $res['reason']);
    }

    public function testIdnDomainHandledWhenIntlAvailable(): void
    {
        if (!function_exists('idn_to_ascii')) {
            $this->markTestSkipped('Intl extension not available for IDN tests.');
        }
        // bücher.de -> xn--bcher-kva.de; TLD 'de' allowed
        $sdk = $this->sdk('de');
        $res = $sdk->validate('user@bücher.de', true);
        // Should pass basic gates; DNS check may depend on environment, so only check TLD/trust gate
        $this->assertTrue($res['trustable']['domain_trust']);
    }
}
