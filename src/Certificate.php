<?php

namespace vakata\asn1;

/**
 * A class for x509 certificate parsing
 */
class Certificate
{
    protected static $x509v3 = [
        'tag' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'tbsCertificate' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'version' => [
                        'tag' => ASN1::TYPE_INTEGER,
                        'mapping' => [1=>'v1','v2','v3']
                    ],
                    'serialNumber' => [
                        'tag' => ASN1::TYPE_INTEGER
                    ],
                    'signature' => [
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
                    'issuer' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'repeat' => [
                            'tag' => ASN1::TYPE_SET,
                            'repeat' => [
                                'tag' => ASN1::TYPE_SEQUENCE,
                                'children' => [
                                    'key' => [
                                        'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                                    ],
                                    'value' => [
                                        'tag' => ASN1::TYPE_ANY,
                                        'optional' => true
                                    ]
                                ]
                            ]
                        ]
                    ],
                    'validity' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'children' => [
                            'notBefore' => [
                                'tag' => ASN1::TYPE_ANY
                            ],
                            'notAfter' => [
                                'tag' => ASN1::TYPE_ANY
                            ]
                        ]
                    ],
                    'subject' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'repeat' => [
                            'tag' => ASN1::TYPE_SET,
                            'repeat' => [
                                'tag' => ASN1::TYPE_SEQUENCE,
                                'children' => [
                                    'key' => [
                                        'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                                    ],
                                    'value' => [
                                        'tag' => ASN1::TYPE_ANY,
                                        'optional' => true
                                    ]
                                ]
                            ]
                        ]
                    ],
                    'SubjectPublicKeyInfo' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'children' => [
                            'algorithm' => [
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
                            'publicKey' => [
                                'tag' => ASN1::TYPE_BIT_STRING
                            ]
                        ]
                    ],
                    'issuerUniqueID' => [
                        'tag' => ASN1::TYPE_BIT_STRING,
                        'optional' => true
                    ],
                    'subjectUniqueID' => [
                        'tag' => ASN1::TYPE_BIT_STRING,
                        'optional' => true
                    ],
                    'extensions' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'repeat' => [
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'extnID' => [ 'tag' => ASN1::TYPE_OBJECT_IDENTIFIER ],
                                'critical' => [ 'tag' => ASN1::TYPE_BOOLEAN, 'optional' => true ],
                                'extnValue' => [ 'tag' => ASN1::TYPE_OCTET_STRING, 'der' => true ]
                            ]
                        ],
                        'optional' => true
                    ]
                ]
            ],
            'signatureAlgorithm' => [
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
            'signatureValue' => [
                'tag' => ASN1::TYPE_BIT_STRING,
            ]
        ]
    ];

    /**
     * Parse a certificate
     * @param  string               $data the certificate
     * @return array                      the parsed certificate
     */
    public static function parseData($data)
    {
        if (strpos($data, '-BEGIN CERTIFICATE-') !== false) {
            $data = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"], '', $data);
            $data = base64_decode($data);
        }
        return ASN1::decodeDER($data, static::$x509v3);
    }

    /**
     * Parse a certificate from a file
     * @param  string               $path the path to the certificate file
     * @return array                      the parsed certificate
     * @codeCoverageIgnore
     */
    public static function parseFile($path)
    {
        return static::parseData(file_get_contents($path));
    }
}
