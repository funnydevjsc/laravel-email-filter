<?php

namespace FunnyDev\EmailFilter;

use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use MaxMind\MinFraud;

class EmailFilterSdk
{
    private array $credentials;
    private string $tld;
    private array $allowedTlds = [];

    public function __construct(string $tld='', array $credentials = [])
    {
        $this->tld = $this->getConfigValue($tld, 'tld');
        // Pre-normalize allowed TLDs from config (pipe-separated string or array)
        $this->allowedTlds = $this->normalizeTldList($this->tld);
        if (empty($credentials)) {
            $this->credentials = $this->getConfigValue($credentials, 'credentials');
        } else {
            $this->credentials = $credentials;
        }
    }

    private function getConfigValue($value, $configKey) {
        return $value ? $value : Config::get('email-filter.'.$configKey);
    }

    /**
     * Normalize a TLD list provided as a pipe-separated string or array.
     * Produces a lowercase, de-duplicated array of ASCII labels.
     */
    private function normalizeTldList($tld): array
    {
        $list = [];
        if (is_array($tld)) {
            $list = $tld;
        } elseif (is_string($tld)) {
            // Split by pipe and remove empties
            $list = preg_split('/\|/', $tld, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }
        // Trim, lowercase, filter invalid/empty, and unique
        $list = array_map(function ($s) {
            $s = strtolower(trim((string)$s));
            return $s;
        }, $list);
        $list = array_values(array_filter($list, function ($s) {
            return $s !== '';
        }));
        $list = array_values(array_unique($list));
        return $list;
    }

    /**
     * Check if the domain's terminal TLD label is allowed, with IDN→ASCII normalization.
     */
    private function isAllowedTld(string $domain): bool
    {
        // If no configured TLDs, allow all
        if (empty($this->allowedTlds)) {
            return true;
        }
        $domain = strtolower($domain);
        if (function_exists('idn_to_ascii')) {
            $ascii = @idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($ascii) {
                $domain = $ascii;
            }
        }
        $pos = strrpos($domain, '.');
        if ($pos === false) {
            return false; // no dot → no TLD
        }
        $tld = substr($domain, $pos + 1);
        if ($tld === '') {
            return false;
        }
        return in_array($tld, $this->allowedTlds, true);
    }

    public function convert_array($data): array
    {
        // Fast, safe conversions without double encoding
        if (empty($data)) {
            return [];
        }
        if (is_array($data)) {
            return $data;
        }
        if (is_string($data)) {
            $decoded = json_decode($data, true);
            return is_array($decoded) ? $decoded : [];
        }
        // Attempt to cast simple objects
        if (is_object($data)) {
            return json_decode(json_encode($data, JSON_PARTIAL_OUTPUT_ON_ERROR), true) ?? [];
        }
        return [];
    }

    public function request(string $method = 'GET', string $url = '', array $param = [], string $response = 'body', bool $verify = false, array $header = ['Connection' => 'keep-alive', 'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'], array $authentication = [], array $options = [], string $proxy = ''): array|string
    {
        if ((! $url) || (! $response)) {
            return '';
        }
        // Merge options, prefer caller-provided values
        $option = ['verify' => $verify];
        if ($proxy) {
            // Preserve provided scheme if present
            if (! Str::startsWith($proxy, ['http://', 'https://'])) {
                $proxy = 'http://' . $proxy;
            }
            $option['proxy'] = $proxy;
        }
        $options = $options + $option;
        if (! $header) {
            $header = ['Connection' => 'keep-alive', 'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'];
        }
        $timeout = (int) ($options['timeout'] ?? 10);
        $instance = Http::withHeaders($header)
            ->timeout($timeout)
            ->withOptions($options);
        if (!empty($authentication['username']) && !empty($authentication['password'])) {
            $instance = $instance->withBasicAuth($authentication['username'], $authentication['password']);
        }
        if ($method == 'GET') {
            $res = $instance->get($url);
        } else {
            $res = $instance->post($url, $param);
        }
        if ($response == 'json') {
            try {
                $json = $res->json();
            } catch (Exception) {
                $json = null;
            }
            return is_array($json) ? $json : $this->convert_array($res->body());
        }

        return $res->body();
    }

    public function init_result(string $email): array
    {
        return [
            'query' => $email,
            'recommend' => true,
            'reason' => '',
            'trustable' => [
                'exist' => true,
                'disposable' => false,
                'blacklist' => 0,
                'fraud_score' => 0,
                'suspicious' => false,
                'high_risk' => false,
                'domain_type' => 'popular',
                'domain_trust' => true,
                'domain_age' => '',
                'dns_valid' => true,
                'username' => true
            ]
        ];
    }

    public function validate(string $email, bool $fast = true, bool $score = false): array
    {
        // Force email lowercase per policy
        $email = strtolower(trim($email));
        $result = $this->init_result($email);

        // Basic format validation first
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $result['recommend'] = false;
            $result['reason'] = 'Invalid email format';
            if ($fast) return $result;
        }

        // Safe domain extraction
        $parts = explode('@', $email, 2);
        if (count($parts) < 2) {
            $result['recommend'] = false;
            $result['reason'] = 'Invalid email format';
            return $result;
        }
        [$localPart, $domain] = $parts;

        // Strict username policy: only a-z, 0-9, dot (.), dash (-), underscore (_)
        // Reject anything else (excluding the plus sign and other symbols) and short-circuit.
        if ($localPart === '' || !preg_match('/^[a-z0-9._-]+$/', $localPart)) {
            $result['trustable']['username'] = false;
            $result['recommend'] = false;
            $result['reason'] = 'This email username was marked as dirty';
            return $result;
        }
        $domain = strtolower($domain);

        // Default domain policy gate (early, fast):
        // - Reject if domain has more than 2 dots (i.e., 4+ labels like a.b.c.d)
        // - Reject if any number exists in the domain
        // This check happens before IDN punycode conversion to avoid false positives
        // from punycoded digits in xn-- labels.
        $labels = preg_split('/\.+/', $domain, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if (count($labels) >= 4 || preg_match('/\d/', $domain)) {
            $result['trustable']['domain_trust'] = false;
            $result['recommend'] = false;
            $result['reason'] = 'This email domain was blocked by default policy';
            return $result;
        }

        // IDNA handling (punycode) if available
        if (function_exists('idn_to_ascii')) {
            $ascii = @idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($ascii) {
                $domain = $ascii;
            }
        }

        // Perform TLD allowed checking (strict policy gate)
        if (!$this->isAllowedTld($domain)) {
            $result['recommend'] = false;
            $result['trustable']['domain_trust'] = false;
            $result['reason'] = 'This email domain was blocked by default policy';
            return $result;
        }

        if ($fast && !$result['recommend']) {
            $result['reason'] = 'This email domain was marked as suspicious';
            return $result;
        }

        // Local disposable domains quick check (cheap)
        $disposableDomains = [
            'mailinator.com',
            'guerrillamail.com',
            'trashmail.com',
            'tempmail.net',
            'yopmail.com',
            'getnada.com',
            'sharklasers.com',
            'inboxbear.com',
            'dispostable.com',
            'cexch.com',
            'comfythings.com',
            'bltiwd.com',
            'spam4.me',
            'osxofulk.com',
            'jkotypc.com',
            'cmhvzylmfc.com',
            'zudpck.com',
            'daouse.com',
            'illubd.com',
            'mkzaso.com',
            'mrotzis.com',
            'xkxkud.com',
            'wnbaldwy.com',
            'bwmyga.com',
            'ozsaip.com',
            'yzcalo.com',
            'forexzig.com',
            'tempmail.id.vn',
            'hathitrannhien.edu.vn',
            'nghienplus.io.vn',
        ];
        if (in_array($domain, $disposableDomains, true)) {
            $result['trustable']['disposable'] = true;
            $result['recommend'] = false;
            $result['reason'] = 'This email was marked as disposable';
            if ($fast) return $result;
        }

        // Quick DNS/MX validation to drop obvious junk
        $hasDns = !function_exists('checkdnsrr') || checkdnsrr($domain, 'MX') || checkdnsrr($domain, 'A');
        if (!$hasDns) {
            $result['trustable']['dns_valid'] = false;
            $result['trustable']['domain_trust'] = false;
            $result['recommend'] = false;
            $result['reason'] = 'This email domain was marked as DNS invalid';
            if ($fast) return $result;
        }

        // Cache for burst protection (fast repeated checks)
        $cacheKey = 'email_filter:'.md5(implode('|', [$email, (int)$fast, (int)$score, $this->tld]));
        if ($fast) {
            try {
                $cached = Cache::get($cacheKey);
                if (is_array($cached)) {
                    return $cached;
                }
            } catch (Exception) {
                // Ignore cache errors
            }
        }

        // Perform quality checking from Maxmind
        try {
            $mmAccount = $this->credentials['maxmind']['account'] ?? null;
            $mmLicense = $this->credentials['maxmind']['license'] ?? null;
            if ($mmAccount && $mmLicense) {
                $mindfraud = new MinFraud($mmAccount, $mmLicense);
                $response = $mindfraud->withEmail([
                    'address' => $email,
                    'domain' => $domain,
                ])->insights();

                $maxmind = $this->convert_array($response);
                try {
                    if (!$result['trustable']['disposable']) {
                        $result['trustable']['disposable'] = $maxmind['email']['is_disposable'];
                    }
                } catch (Exception) {}
                if ($fast && $result['trustable']['disposable']) {
                    $result['reason'] = 'This email was marked as disposable';
                    $result['recommend'] = false;
                    return $result;
                }

                try {
                    if (!$result['trustable']['high_risk']) {
                        $result['trustable']['high_risk'] = $maxmind['email']['is_high_risk'];
                    }
                } catch (Exception) {}
                if ($fast && $result['trustable']['high_risk']) {
                    $result['reason'] = 'This email was marked as high risk';
                    $result['recommend'] = false;
                    return $result;
                }

                try {
                    $result['trustable']['domain_age'] = $maxmind['email']['domain']['first_seen'];
                } catch (Exception) {}

                try {
                    $result['trustable']['fraud_score'] = max($result['trustable']['fraud_score'], $maxmind['risk_score']);
                } catch (Exception) {
                    $result['trustable']['fraud_score'] = round($maxmind['risk_score']);
                }
            }
        } catch (Exception) {}

        // Perform quality checking from cleantalk
        try {
            if (!empty($this->credentials['cleantalk'])) {
                $cleantalk = $this->request('GET', 'https://api.cleantalk.org/?method_name=spam_check&auth_key=' . $this->credentials['cleantalk'] . '&email=' . urlencode($email), [], 'json', false, [], [], ['timeout' => $fast ? 3 : 10]);

                if ($result['trustable']['exist']) {
                    $result['trustable']['exist'] = ! (isset($cleantalk['data'][$email]['exists']) && ($cleantalk['data'][$email]['exists'] === 0));
                    if ($fast && ! $result['trustable']['exist']) {
                        $result['reason'] = 'This email was marked as non-existent';
                        $result['recommend'] = false;
                        return $result;
                    }
                }

                if (!$result['trustable']['disposable']) {
                    $result['trustable']['disposable'] = (isset($cleantalk['data'][$email]['disposable_email']) && ($cleantalk['data'][$email]['disposable_email'] === 1));
                    if ($fast && $result['trustable']['disposable']) {
                        $result['reason'] = 'This email was marked as disposable';
                        $result['recommend'] = false;
                        return $result;
                    }
                }

                if (isset($cleantalk['data'][$email]['spam_rate'])) {
                    $result['trustable']['fraud_score'] = max($result['trustable']['fraud_score'], (int) round($cleantalk['data'][$email]['spam_rate'] * 100));
                }
                if ($fast && $score && ($result['trustable']['fraud_score'] >= 75)) {
                    $result['reason'] = 'This email was marked as fraudulent';
                    $result['recommend'] = false;
                    return $result;
                }
            }
        } catch (Exception) {}

        // Perform quality checking from apivoid
        try {
            if (!empty($this->credentials['apivoid'])) {
                $apivoid = $this->request('GET', 'https://endpoint.apivoid.com/emailverify/v1/pay-as-you-go/?key=' . $this->credentials['apivoid'] . '&email=' . urlencode($email), [], 'json', false, [], [], ['timeout' => $fast ? 3 : 10]);

                if (isset($apivoid['data']['score'])) {
                    $result['trustable']['fraud_score'] = max($result['trustable']['fraud_score'], (int) round($apivoid['data']['score']));
                }
                if ($fast && $score && ($result['trustable']['fraud_score'] >= 75)) {
                    $result['reason'] = 'This email was marked as fraudulent';
                    $result['recommend'] = false;
                    return $result;
                }

                $result['trustable']['suspicious'] = (bool)($apivoid['data']['suspicious_email'] ?? false);
                if ($fast && $result['trustable']['suspicious']) {
                    $result['reason'] = 'This email was marked as suspicious';
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['disposable']) {
                    $result['trustable']['disposable'] = (bool)($apivoid['data']['disposable'] ?? false);
                    if ($fast && $result['trustable']['disposable']) {
                        $result['reason'] = 'This email was marked as disposable';
                        $result['recommend'] = false;
                        return $result;
                    }
                }

                if (!empty($apivoid['data']['domain_popular'])) {
                    $result['trustable']['domain_type'] = 'popular';
                }
                $tmp = ['police_domain', 'government_domain', 'educational_domain'];
                foreach ($tmp as $t) {
                    if (!empty($apivoid['data'][$t])) {
                        $result['trustable']['domain_type'] = explode('_', $t)[0];
                    }
                }
                if ($result['trustable']['domain_trust']) {
                    $result['trustable']['domain_trust'] = (bool)($apivoid['data']['has_a_records'] ?? false);
                    $tmp = ['has_mx_records', 'has_spf_records', 'dmarc_configured', 'valid_tld', 'is_spoofable'];
                    foreach ($tmp as $t) {
                        if (empty($apivoid['data'][$t])) {
                            $result['trustable']['domain_trust'] = false;
                            if ($fast) {
                                $result['reason'] = 'This email domain was marked as suspicious';
                                $result['recommend'] = false;
                                return $result;
                            }
                        }
                    }
                    $tmp = ['suspicious_domain', 'dirty_words_domain', 'risky_tld'];
                    foreach ($tmp as $t) {
                        if (!empty($apivoid['data'][$t])) {
                            $result['trustable']['domain_trust'] = false;
                            if ($fast) {
                                $result['reason'] = 'This email domain was marked as suspicious';
                                $result['recommend'] = false;
                                return $result;
                            }
                        }
                    }

                }
                if ($fast && !$result['trustable']['domain_trust']) {
                    $result['reason'] = 'This email domain was marked as suspicious';
                    $result['recommend'] = false;
                    return $result;
                }
                if ($fast && $result['trustable']['disposable']) {
                    $result['reason'] = 'This email was marked as disposable';
                    $result['recommend'] = false;
                    return $result;
                }

                if ($result['trustable']['username']) {
                    $tmp = ['suspicious_username', 'dirty_words_username'];
                    foreach ($tmp as $t) {
                        if (($result['trustable']['username']) && (!empty($apivoid['data'][$t]))) {
                            $result['trustable']['username'] = false;
                        }
                    }
                }
                if ($fast && !$result['trustable']['username']) {
                    $result['reason'] = 'This email username was marked as dirty';
                    $result['recommend'] = false;
                    return $result;
                }

                if ($apivoid['data']['should_block']) {
                    $result['reason'] = 'This email was marked as should be blocked';
                    $result['recommend'] = false;
                    if ($fast) {
                        return $result;
                    }
                }

                if (isset($apivoid['score'])) {
                    $result['trustable']['fraud_score'] = max($result['trustable']['fraud_score'], (int) round($apivoid['score']));
                }
                if ($fast && $score && ($result['trustable']['fraud_score'] >= 75)) {
                    $result['recommend'] = false;
                    $result['reason'] = 'This email was marked as fraudulent';
                    return $result;
                }
            }
        } catch (Exception) {}

        // Perform quality checking from ipqualityscore
        try {
            if (!empty($this->credentials['ipqualityscore'])) {
                $ipqualityscore = $this->request('GET', 'https://ipqualityscore.com/api/json/email/' . $this->credentials['ipqualityscore'] . '/' . urlencode($email) . '?strictness=1', [], 'json', false, [], [], ['timeout' => $fast ? 3 : 10]);

                if ($result['trustable']['exist']) {
                    $result['trustable']['exist'] = (bool)($ipqualityscore['valid'] ?? false);
                }
                if ($fast && !$result['trustable']['exist']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['disposable']) {
                    $result['trustable']['disposable'] = (bool)($ipqualityscore['disposable'] ?? false);
                }
                if ($fast && $result['trustable']['disposable']) {
                    $result['reason'] = 'This email was marked as disposable';
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['disposable']) {
                    $result['trustable']['disposable'] = (bool)($ipqualityscore['catch_all'] ?? false);
                }
                if ($fast && $result['trustable']['disposable']) {
                    $result['reason'] = 'This email was marked as disposable';
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['disposable']) {
                    $result['trustable']['disposable'] = (bool)($ipqualityscore['generic'] ?? false);
                }
                if ($fast && $result['trustable']['disposable']) {
                    $result['reason'] = 'This email was marked as disposable';
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['suspicious']) {
                    $result['trustable']['suspicious'] = (bool)($ipqualityscore['recent_abuse'] ?? false);
                }
                if ($fast && $result['trustable']['suspicious']) {
                    $result['reason'] = 'This email was marked as suspicious';
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['suspicious']) {
                    $result['trustable']['suspicious'] = (bool)($ipqualityscore['honeypot'] ?? false);
                }
                if ($fast && $result['trustable']['suspicious']) {
                    $result['reason'] = 'This email domain was marked as suspicious or spam';
                    $result['recommend'] = false;
                    return $result;
                }

                if ($result['trustable']['dns_valid']) {
                    $result['trustable']['dns_valid'] = (bool)($ipqualityscore['dns_valid'] ?? false);
                    if ($result['trustable']['dns_valid']) {
                        if (($ipqualityscore['overall_score'] ?? null) === 0) {
                            $result['trustable']['dns_valid'] = false;
                            $result['recommend'] = false;
                        }
                    }
                    if ($fast && !$result['trustable']['dns_valid']) {
                        $result['reason'] = 'This email domain was marked as DNS invalid';
                        $result['recommend'] = false;
                        return $result;
                    }

                    if ($result['trustable']['dns_valid']) {
                        if (($ipqualityscore['smtp_score'] ?? null) === -1) {
                            $result['trustable']['dns_valid'] = false;
                            $result['recommend'] = false;
                        }
                    }
                    if ($fast && !$result['trustable']['dns_valid']) {
                        $result['reason'] = 'This email domain was marked as DNS invalid';
                        $result['recommend'] = false;
                        return $result;
                    }
                }

                if (isset($ipqualityscore['fraud_score'])) {
                    $result['trustable']['fraud_score'] = max($result['trustable']['fraud_score'], (int) round($ipqualityscore['fraud_score']));
                }
                if ($fast && $score && ($result['trustable']['fraud_score'] >= 75)) {
                    $result['recommend'] = false;
                    $result['reason'] = 'This email was marked as fraudulent';
                }
            }
        } catch (Exception) {}

        try {
            if ($result['trustable']['fraud_score'] > 100) {
                $result['trustable']['fraud_score'] = 100;
            }
            if ($result['trustable']['fraud_score'] < 0) {
                $result['trustable']['fraud_score'] = 0;
            }
            if ($fast && $score && ($result['trustable']['fraud_score'] >= 75)) {
                $result['reason'] = 'This email was marked as fraudulent';
                $result['recommend'] = false;
            }
        } catch (Exception) {
            $result['trustable']['fraud_score'] = 0;
        }

        $total = 0;
        // Perform blacklist checking from poste
        try {
            if (!empty($this->credentials['poste']) && (strtolower($this->credentials['poste']) !== 'off')) {
                $response = $this->request('GET', 'https://poste.io/api/web-dnsbl?query=' . $domain);
                if ($response) {
                    $this_total = substr_count($response, '"name"');
                    $total += $this_total;
                    $result['trustable']['blacklist'] += $this_total - substr_count($response, '"ok"') - substr_count($response, '"error"');
                }
            }
        } catch (Exception) {}

        // Perform blacklist checking from site24x7
        try {
            if (!empty($this->credentials['site247']) && (strtolower($this->credentials['site247']) !== 'off')) {
                $param = [
                    'execute' => 'performRBLCheck',
                    'method' => 'performRBLCheck',
                    'url' => $domain,
                    'hostName' => $domain,
                    'timestamp' => time()
                ];
                $header = [
                    'Connection' => 'keep-alive',
                    'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
                    'sec-ch-ua' => '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
                    'sec-ch-ua-platform' => '"macOS"',
                    'sec-ch-ua-mobile' => '?0',
                    'X-Requested-With' => 'XMLHttpRequest',
                    'Referer' => 'https://www.site24x7.com/tools/blacklist-check.html'
                ];
                $response = $this->request('POST', 'https://www.site24x7.com/tools/action.do', $param, 'body', false, $header, [], ['timeout' => $fast ? 3 : 10]);
                if ($response) {
                    $total += 19;
                    $result['trustable']['blacklist'] += substr_count($response, 'Blocklisted in ');
                }
            }
        } catch (Exception) {}

        if (($total === 0) || ($result['trustable']['blacklist'] === 0)) {
            $result['trustable']['blacklist'] = 0;
        } else {
            $result['trustable']['blacklist'] = round(($result['trustable']['blacklist'] / $total) * 100, 2);
        }

        if ($fast && ($result['trustable']['blacklist'] >= 30)) {
            $result['reason'] = 'This email was marked as blacklisted';
            $result['recommend'] = false;
            return $result;
        }

        // Cache only final results
        try { Cache::put($cacheKey, $result, 300); } catch (Exception) {}

        return $result;
    }
}
