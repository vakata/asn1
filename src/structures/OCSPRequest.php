<?php

namespace vakata\asn1\structures;

use \vakata\asn1\ASN1;
use \vakata\asn1\Encoder;

class OCSPRequest extends Structure
{
    public static function generate(
        string $algorithm,
        string $issuerNameHash,
        string $issuerKeyHash,
        string $serialNumber
    ) {
        $src = [
            'tbsRequest' => [
                'requestList' => [
                    [
                        'reqCert' => [
                            'hashAlgorithm' => [
                                'algorithm' => ASN1::$oids[strtolower($algorithm)] ?? ASN1::$oids['md5']
                            ],
                            'issuerNameHash' => $issuerNameHash,
                            'issuerKeyHash' => $issuerKeyHash,
                            'serialNumber' => $serialNumber,
                        ]
                    ]
                ]
            ]
        ];
        return Encoder::encode($src, static::map());
    }

    public static function map()
    {
        return [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'tbsRequest' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'version' => [
                            'tag' => ASN1::TYPE_INTEGER,
                            'name' => 0,
                            'implicit' => false,
                            'map' => [1=>'v1'],
                            'optional' => true
                        ],
                        'requestorName' => [
                            'tag' => ASN1::TYPE_GENERAL_STRING,
                            'optional' => true,
                            'name' => 1,
                            'implicit' => false,
                        ],
                        'requestList' => [
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'repeat' => [
                                'tag' => ASN1::TYPE_SEQUENCE,
                                'children' => [
                                    'reqCert' => [
                                        'tag' => ASN1::TYPE_SEQUENCE,
                                        'children' => [
                                            'hashAlgorithm' => Common::AlgorithmIdentifier(),
                                            'issuerNameHash' => [
                                                'tag' => ASN1::TYPE_OCTET_STRING,
                                            ],
                                            'issuerKeyHash' => [
                                                'tag' => ASN1::TYPE_OCTET_STRING,
                                            ],
                                            'serialNumber' => [
                                                'tag' => ASN1::TYPE_INTEGER,
                                                'base' => 16
                                            ],
                                        ]
                                    ],
                                    'extensions' => Common::extensions() + [
                                        'name' => 0,
                                        'implicit' => false,
                                        'optional' => true
                                    ]
                                ]
                            ]
                        ],
                        'extensions' => Common::extensions() + ['name' => 2, 'implicit' => false, 'optional' => true ]
                    ]
                ],
                'signature' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'name' => 0,
                    'implicit' => false,
                    'optional' => true,
                    'children' => [
                        'signatureAlgorithm' => Common::AlgorithmIdentifier(),
                        'signature' => [
                            'tag' => ASN1::TYPE_BIT_STRING,
                        ],
                        'certs' => [
                            'tag' => ASN1::TYPE_ANY,
                            'name' => 0,
                            'implicit' => false,
                            'optional' => true
                        ]
                    ]
                ]
            ]
        ];
    }
}
