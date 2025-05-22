<?php

return [
    'tld' => env('EMAIL_FILTER_TLD', 'vn|com|net|org|uk|us|io|dev'),
    'credentials' => [
        'poste' => env('EMAIL_FILTER_POSTE', 'ON'),
        'site247' => env('EMAIL_FILTER_SITE247', 'ON'),
        'maxmind' => [
            'account' => env('EMAIL_FILTER_MAXMIND_ACCOUNT', ''),
            'license' => env('EMAIL_FILTER_MAXMIND_LICENSE', ''),
        ],
        'cleantalk' => env('EMAIL_FILTER_CLEANTALK_KEY', ''),
        'apivoid' => env('EMAIL_FILTER_APIVOID_KEY', ''),
        'ipqualityscore' => env('EMAIL_FILTER_IPQUALITYSCORE_KEY', '')
    ]
];