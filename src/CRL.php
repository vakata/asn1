<?php

namespace vakata\asn1;

/**
 * A class for CRL parsing
 */
class CRL
{
    protected static $crl = [
        'tag' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'tbsCertList' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'version' => [
                        'tag' => ASN1::TYPE_INTEGER,
                        'mapping' => [1=>'v1','v2','v3']
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
                    'thisUpdate' => [
                        'tag' => ASN1::TYPE_CHOICE,
                        'children' => [
                            [ 'tag' => ASN1::TYPE_GENERALIZED_TIME ],
                            [ 'tag' => ASN1::TYPE_UTC_TIME ]
                        ]
                    ],
                    'nextUpdate' => [
                        'tag' => ASN1::TYPE_CHOICE,
                        'optional' => true,
                        'children' => [
                            [ 'tag' => ASN1::TYPE_GENERALIZED_TIME ],
                            [ 'tag' => ASN1::TYPE_UTC_TIME ]
                        ]
                    ],
                    'revokedCertificates' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'repeat' => [
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'userCertificate' => [
                                    'tag' => ASN1::TYPE_INTEGER,
                                    'base' => 16
                                ],
                                'revocationDate' => [
                                    'tag' => ASN1::TYPE_CHOICE,
                                    'children' => [
                                        [ 'tag' => ASN1::TYPE_GENERALIZED_TIME ],
                                        [ 'tag' => ASN1::TYPE_UTC_TIME ]
                                    ]
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
                        ]
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
     * Parse a CRL
     * @param  string               $data the CRL
     * @return array                      the parsed CRL
     */
    public static function parseData($data)
    {
        if (strpos($data, '-BEGIN CERTIFICATE-') !== false) {
            $data = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"], '', $data);
            $data = base64_decode($data);
        }
        return ASN1::decodeDER($data, static::$crl);
    }

    /**
     * Parse a CRL from a file
     * @param  string               $path the path to the certificate file
     * @return array                      the parsed CRL
     * @codeCoverageIgnore
     */
    public static function parseFile($path)
    {
        return static::parseData(file_get_contents($path));
    }
}
