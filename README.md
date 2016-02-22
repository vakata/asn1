# asn1

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Build Status][ico-travis]][link-travis]
[![Code Climate][ico-cc]][link-cc]
[![Tests Coverage][ico-cc-coverage]][link-cc]

Am ASN1 encoder / decoder.

## Install

Via Composer

``` bash
$ composer require vakata/asn1
```

## Usage

``` php
// Example 1: generating a Time-Stamp Request

// first configure the mapping (the structure)
$tsq = [
    'type' => ASN1::TYPE_SEQUENCE,
    'children' => [
        'version' => [
            'type' => ASN1::TYPE_INTEGER,
            'mapping' => [1=>'v1','v2','v3']
        ],
        'messageImprint' => [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
               'hashAlgorithm' => [
                    'type' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        "algorithm" => [
                            'type' => ASN1::TYPE_OBJECT_IDENTIFIER
                        ],
                        'parameters' => [
                            'type' => ASN1::TYPE_ANY,
                            'optional' => true
                        ]
                    ]
               ],
               'hashedMessage' => [
                    'type' => ASN1::TYPE_OCTET_STRING
               ]
            ]
        ],
        'reqPolicy' => [
            'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
            'optional' => true
        ],
        'nonce' => [
            'type' => ASN1::TYPE_INTEGER,
            'optional' => true
        ],
        'certReq' => [
            'type' => ASN1::TYPE_BOOLEAN,
            'optional' => true
        ]
    ]
];

// then collect all values
$src = [
    'version' => 'v1',
    'messageImprint' => [
        'hashAlgorithm' => [ "algorithm" => 'sha1' ],
        'hashedMessage' => base64_encode(sha1("asdf", true)),
    ],
    'certReq' => true,
    'nonce' => rand(0, PHP_INT_MAX)
];

// finally produce the TSQ
$res = ASN1::encodeDER($src, $tsq); // raw output
// the result can be checked using:
// openssl ts -query -in FILE.tsq -text

// Example 2: decode a DER encoded object (Time-Stamp Request)
ASN1::decodeDER($res); // deeply nested definition

// Example 3: decode a DER using a map (the one from the previous example)
ASN1::decodeDER($res, $tsq); // the same as `$src`

// Example 4: partially decode a DER encoded Time-Stamp Response:
$tsr = [
    'type' => ASN1::TYPE_SEQUENCE,
    'children' => [
        'status' => [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'status' => [
                    'type' => ASN1::TYPE_INTEGER,
                    'mapping' => [
                        'granted',
                        'grantedWithMods',
                        'rejection',
                        'waiting',
                        'revocationWarning',
                        'revocationNotification'
                    ]
                ],
                'statusString' => [
                    'type' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'data' => [
                            'type' =>ASN1::TYPE_UTF8_STRING
                        ]
                    ]
                ],
                'failInfo' => [
                    'type' => ASN1::TYPE_BIT_STRING,
                    'optional' => true
                ]
            ]
        ],
        'timeStampToken' => [
            'tag' => ASN1::TYPE_SEQUENCE,
            'optional' => true,
            'children' => [
                'contentType' => ['tag' => ASN1::TYPE_OBJECT_IDENTIFIER ],
                'signedData' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'version' => ['tag' => ASN1::TYPE_INTEGER ],
                        'algorithms' => [
                            'tag' => ASN1::TYPE_SET,
                            'children' => [
                                'hashAlgorithm' => [
                                     'tag' => ASN1::TYPE_SEQUENCE,
                                     'children' => [
                                         "algorithm" => [
                                             'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                                         ],
                                         'parameters' => [
                                             'tag' => ASN1::TYPE_ANY,
                                             'optional' => true
                                         ]
                                     ]
                                ],
                            ],
                        ],
                        "tokenInfo" => ['tag' => ASN1::TYPE_ANY_RAW]
                    ]
                ]
            ]
        ]
    ]
];
$res = ASN1::decodeDER($rawInput, $tsr);
if (in_array($res['status']['status'], [ 'granted', 'grantedWithMods'])) {
    // timestamp was granted - we can now extract all related data
    $token = [
        'tag' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => ['tag' => ASN1::TYPE_INTEGER, 'mapping' => [1 => 'v1','v2','v3'] ],
            'policy' =>  ['tag' => ASN1::TYPE_OBJECT_IDENTIFIER, 'optional' => true ],
            'messageImprint' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'children' => [
                   'hashAlgorithm' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'children' => [
                            "algorithm" => [
                                'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                            ],
                            'parameters' => [
                                'tag' => ASN1::TYPE_ANY,
                                'optional' => true
                            ]
                        ]
                   ],
                   'hashedMessage' => [
                        'tag' => ASN1::TYPE_OCTET_STRING,
                        'optional' => true // non-optional
                   ]
                ]
            ],
            'serialNumber' => ['tag' => ASN1::TYPE_INTEGER, 'optional' => true ], // non-optional
            'genTime' => ['tag' => ASN1::TYPE_GENERALIZED_TIME], // GeneralizedTime (non-optional]
            'accuracy' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'optional' => true,
                'children' => [
                    'seconds' => ['tag' => ASN1::TYPE_ANY, 'optional' => true ],
                    'millis' => ['tag' => ASN1::TYPE_ANY, 'optional' => true ],
                    'micros' => ['tag' => ASN1::TYPE_ANY, 'optional' => true ],
                ]
            ],
            'ordering' => [
                'tag' => ASN1::TYPE_BOOLEAN,
                'optional' => true
            ],
            'nonce' => [
                'tag' => ASN1::TYPE_INTEGER,
                'optional' => true
            ],
            'tsa' => ['tag' => ASN1::TYPE_ANY_RAW, 'optional' => true]
        ]
    ];
    $token = ASN1::decodeDER(
        $res['timeStampToken']["signedData"]["tokenInfo"][1],
        $token
    );
}
```

Read more in the [API docs](docs/README.md)

## Testing

``` bash
$ composer test
```


## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email github@vakata.com instead of using the issue tracker.

## Credits

- [vakata][link-author]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information. 

[ico-version]: https://img.shields.io/packagist/v/vakata/asn1.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-travis]: https://img.shields.io/travis/vakata/asn1/master.svg?style=flat-square
[ico-scrutinizer]: https://img.shields.io/scrutinizer/coverage/g/vakata/asn1.svg?style=flat-square
[ico-code-quality]: https://img.shields.io/scrutinizer/g/vakata/asn1.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/vakata/asn1.svg?style=flat-square
[ico-cc]: https://img.shields.io/codeclimate/github/vakata/asn1.svg?style=flat-square
[ico-cc-coverage]: https://img.shields.io/codeclimate/coverage/github/vakata/asn1.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/vakata/asn1
[link-travis]: https://travis-ci.org/vakata/asn1
[link-scrutinizer]: https://scrutinizer-ci.com/g/vakata/asn1/code-structure
[link-code-quality]: https://scrutinizer-ci.com/g/vakata/asn1
[link-downloads]: https://packagist.org/packages/vakata/asn1
[link-author]: https://github.com/vakata
[link-contributors]: ../../contributors
[link-cc]: https://codeclimate.com/github/vakata/asn1

