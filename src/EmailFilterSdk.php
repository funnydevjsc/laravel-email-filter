<?php

namespace FunnyDev\EmailFilter;

use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use MaxMind\MinFraud;

class EmailFilterSdk
{
    private array $credentials;
    private string $tld;

    public function __construct(string $tld='', array $credentials = [])
    {
        $this->tld = $this->getConfigValue($tld, 'tld');
        if (empty($credentials)) {
            $this->credentials = $this->getConfigValue($credentials, 'credentials');
        } else {
            $this->credentials = $credentials;
        }
    }

    private function getConfigValue($value, $configKey) {
        return $value ? $value : Config::get('email-filter.'.$configKey);
    }

    public function convert_array($data): array
    {
        if (! $data) {
            return [];
        }
        $tmp = json_decode(json_encode($data, true), true);
        if (! is_array($tmp)) {
            $tmp = json_decode($tmp, true);
        }
        return $tmp;
    }

    public function request(string $method = 'GET', string $url = '', array $param=[], string $response = 'body', bool $verify = false, array $header = ['Connection' => 'keep-alive', 'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'], array $authentication = [], array $options = [], string $proxy = ''): array|string
    {
        if ((! $url) || (! $response)) {
            return '';
        }
        $option = ['verify' => $verify];
        if ($proxy) {
            if (! Str::startsWith($proxy, 'http')) {
                $proxy = 'http://'.$proxy;
                $option['proxy'] = $proxy;
            }
        }
        foreach ($option as $c => $v) {
            $options[$c] = $v;
        }
        if (! $header) {
            $header = ['Connection' => 'keep-alive', 'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'];
        }
        if ($authentication) {
            $instance = Http::withHeaders($header)->timeout(10)->withBasicAuth($authentication['username'], $authentication['password'])->withOptions($options);
        } else {
            $instance = Http::withHeaders($header)->timeout(10)->withOptions($options);
        }
        if ($method == 'GET') {
            $res = $instance->get($url);
        } else {
            $res = $instance->post($url, $param);
        }
        if ($response == 'json') {
            return $this->convert_array($res->body());
        }

        return $res->body();
    }

    public function init_result(string $email): array
    {
        return [
            'query' => $email,
            'recommend' => true,
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
                'dns_valid' => false,
                'username' => true
            ]
        ];
    }

    public function validate(string $email, bool $fast=false): array
    {
        $domain = explode('@', $email)[1];
        $result = $this->init_result($email);

        // Perform ltd allowed checking
        $regex = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.('.$this->tld.')$/';
        if (!preg_match($regex, $email)) {
            $result['recommend'] = false;
            $result['trustable']['domain_trust'] = false;
        }

        if ($fast && !$result['recommend']) {
            return $result;
        }

        // Perform quality checking from Maxmind
        try {
            if ($this->credentials['maxmind']['account'] && $this->credentials['maxmind']['license']) {
                $mindfraud = new MinFraud($this->credentials['maxmind']['account'], $this->credentials['maxmind']['license']);
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
                    $result['recommend'] = false;
                    return $result;
                }

                try {
                    if (!$result['trustable']['free_email']) {
                        $result['trustable']['free_email'] = $maxmind['email']['is_free'];
                    }
                } catch (Exception) {}
                if ($fast && $result['trustable']['free_email']) {
                    $result['recommend'] = false;
                    return $result;
                }

                try {
                    if (!$result['trustable']['high_risk']) {
                        $result['trustable']['high_risk'] = $maxmind['email']['is_high_risk'];
                    }
                } catch (Exception) {}
                if ($fast && $result['trustable']['high_risk']) {
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

        // Perform quality checking from apivoid
        try {
            if ($this->credentials['apivoid']) {
                $apivoid = $this->request('GET', 'https://endpoint.apivoid.com/emailverify/v1/pay-as-you-go/?key=' . $this->credentials['apivoid'] . '&email=' . $email, [], 'json');
                $result['trustable']['fraud_score'] = 100 - round($apivoid['data']['score']);
                $result['trustable']['suspicious'] = $apivoid['data']['suspicious_email'];
                if ($fast && $result['trustable']['suspicious']) {
                    $result['recommend'] = false;
                    return $result;
                }

                $result['trustable']['disposable'] = $apivoid['data']['disposable'];
                if ($fast && $result['trustable']['disposable']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if ($apivoid['data']['domain_popular']) {
                    $result['trustable']['domain_type'] = 'popular';
                }
                $tmp = ['police_domain', 'government_domain', 'educational_domain'];
                foreach ($tmp as $t) {
                    if ($apivoid['data'][$t]) {
                        $result['trustable']['domain_type'] = explode('_', $t)[0];
                    }
                }
                if ($result['trustable']['domain_trust']) {
                    $result['trustable']['domain_trust'] = $apivoid['data']['has_a_records'];
                    $tmp = ['has_mx_records', 'has_spf_records', 'dmarc_configured', 'suspicious_domain', 'dirty_words_domain', 'risky_tld'];
                    foreach ($tmp as $t) {
                        if ($result['trustable']['domain_trust']) {
                            $result['trustable']['domain_trust'] = $apivoid['data'][$t];
                        }
                    }
                }
                if ($fast && $result['trustable']['domain_trust']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if ($result['trustable']['free_email']) {
                    $result['trustable']['free_email'] = $apivoid['data']['free_email'];
                    $tmp = ['russian_free_email', 'china_free_email'];
                    foreach ($tmp as $t) {
                        if ($result['trustable']['domain_trust']) {
                            $result['trustable']['domain_trust'] = $apivoid['data'][$t];
                        }
                    }
                }
                if ($fast && $result['trustable']['free_email']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if ($result['trustable']['username']) {
                    $tmp = ['suspicious_username', 'dirty_words_username'];
                    foreach ($tmp as $t) {
                        if (($result['trustable']['username']) && ($apivoid['data'][$t])) {
                            $result['trustable']['username'] = false;
                        }
                    }
                }
                if ($fast && !$result['trustable']['username']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if ($apivoid['data']['should_block']) {
                    $result['recommend'] = false;
                    if ($fast) {
                        return $result;
                    }
                }
            }
        } catch (Exception) {}

        // Perform quality checking from ipqualityscore
        try {
            if ($this->credentials['ipqualityscore']) {
                $ipqualityscore = $this->request('GET', 'https://ipqualityscore.com/api/json/email/' . $this->credentials['ipqualityscore'] . '/' . $email . '?strictness=1', [], 'json');
                if ($result['trustable']['exist']) {
                    $result['trustable']['exist'] = $ipqualityscore['valid'];
                }
                if ($fast && !$result['trustable']['exist']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['disposable']) {
                    $result['trustable']['disposable'] = $ipqualityscore['disposable'];
                }
                if ($fast && $result['trustable']['disposable']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['disposable']) {
                    $result['trustable']['disposable'] = $ipqualityscore['catch_all'];
                }
                if ($fast && $result['trustable']['disposable']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['disposable']) {
                    $result['trustable']['disposable'] = $ipqualityscore['generic'];
                }
                if ($fast && $result['trustable']['disposable']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['suspicious']) {
                    $result['trustable']['suspicious'] = $ipqualityscore['recent_abuse'];
                }
                if ($fast && $result['trustable']['suspicious']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if (!$result['trustable']['suspicious']) {
                    $result['trustable']['suspicious'] = $ipqualityscore['honeypot'];
                }
                if ($fast && $result['trustable']['suspicious']) {
                    $result['recommend'] = false;
                    return $result;
                }

                if ($result['trustable']['dns_valid']) {
                    $result['trustable']['dns_valid'] = $ipqualityscore['dns_valid'];
                    if ($result['trustable']['dns_valid']) {
                        if ($ipqualityscore['overall_score'] == 0) {
                            $result['trustable']['dns_valid'] = false;
                            $result['recommend'] = false;
                        }
                    }
                    if ($fast && !$result['trustable']['dns_valid']) {
                        $result['recommend'] = false;
                        return $result;
                    }

                    if ($result['trustable']['dns_valid']) {
                        if ($ipqualityscore['smtp_score'] == -1) {
                            $result['trustable']['dns_valid'] = false;
                            $result['recommend'] = false;
                        }
                    }
                    if ($fast && !$result['trustable']['dns_valid']) {
                        $result['recommend'] = false;
                        return $result;
                    }
                }

                try {
                    $result['trustable']['fraud_score'] = max($result['trustable']['fraud_score'], round($ipqualityscore['fraud_score']));
                } catch (Exception) {
                    $result['trustable']['fraud_score'] = round($ipqualityscore['fraud_score']);
                }
            }
        } catch (Exception) {}

        // Parse result
        try {
            if ($result['trustable']['fraud_score'] > 100) {
                $result['trustable']['fraud_score'] = 100;
            }
            if ($result['trustable']['fraud_score'] < 0) {
                $result['trustable']['fraud_score'] = 0;
            }
        } catch (Exception) {
            $result['trustable']['fraud_score'] = 0;}
        try {
            if ($result['trustable']['blacklist'] > 25) {
                $result['recommend'] = false;
            } elseif ($result['trustable']['fraud_score'] >= 75) {
                $result['recommend'] = false;
            }
        } catch (Exception) {}
        try {
            if (!$result['trustable']['exist']) {
                $result['recommend'] = false;
            }
        } catch (Exception) {}
        try {
            if ($result['trustable']['high_risk']) {
                $result['recommend'] = false;
            }
        } catch (Exception) {}
        try {
            if (!$result['trustable']['dns_valid']) {
                $result['recommend'] = false;
            }
        } catch (Exception) {}
        try {
            if (!$result['trustable']['suspicious']) {
                $result['recommend'] = false;
            }
        } catch (Exception) {}
        try {
            if (!$result['trustable']['disposable']) {
                $result['recommend'] = false;
            }
        } catch (Exception) {}

        $total = 0;
        // Perform blacklist checking from poste
        try {
            if ($this->credentials['poste']) {
                $response = $this->request('GET', 'https://poste.io/api/web-dnsbl?query=' . $domain);
                if ($response) {
                    $this_total = substr_count($response, '"name"');
                    $total += $this_total;
                    $result['trustable']['blacklist'] += $this_total - substr_count($response, '"ok"') - substr_count($response, '"error"');
                }
            }
        } catch (Exception) {}

        // Perform blacklist checking from site24x7.com
        try {
            if ($this->credentials['site247']) {
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
                $response = $this->request('POST', 'https://www.site24x7.com/tools/action.do', $param, 'body', false, $header);
                if ($response) {
                    $total += 19;
                    $result['trustable']['blacklist'] += substr_count($response, 'Blocklisted in ');
                }
            }
        } catch (Exception) {}

        $result['trustable']['blacklist'] = round(($result['trustable']['blacklist'] / $total) * 100, 2);

        if ($fast && ($result['trustable']['blacklist'] > 25)) {
            $result['recommend'] = false;
            return $result;
        }

        return $result;
    }
}
