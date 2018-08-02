<?php

namespace vakata\asn1;

/**
 * A class for OCSP parsing
 */
class OCSP
{
    protected static $request = [
        'tag' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'tbsRequest' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'version' => [
                        'tag' => ASN1::TYPE_INTEGER,
                        'mapping' => [1=>'v1'],
                        'optional' => true
                    ],
                    'requestorName' => [
                        'tag' => ASN1::TYPE_GENERAL_STRING,
                        'optional' => true
                    ],
                    'requestList' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'repeat' => [
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'reqCert' => [
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
            'signature' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'optional' => true,
                'children' => [
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
                    'signature' => [
                        'tag' => ASN1::TYPE_BIT_STRING,
                    ],
                    'certs' => [
                        'tag' => ASN1::TYPE_ANY,
                        'optional' => true
                    ]
                ]
            ]
        ]
    ];
    protected static $response = [
        'tag' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'responseStatus' => [
                'tag' => ASN1::TYPE_ENUMERATED,
                'mapping' => [
                    'successful',
                    'malformedRequest',
                    'internalError',
                    'tryLater',
                    '',
                    'sigRequired',
                    'unauthorized'
                ]
            ],
            'responseBytes' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'optional' => true,
                'children' => [
                    'responseType' => [
                        'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                    ],
                    'response' => [
                        'tag' => ASN1::TYPE_OCTET_STRING,
                        'der' => true,
                        'mapping' => [
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'tbsResponseData' => [
                                    'tag' => ASN1::TYPE_SEQUENCE,
                                    'children' => [
                                        'version' => [
                                            'tag' => ASN1::TYPE_INTEGER,
                                            'mapping' => [1=>'v1'],
                                            'optional' => true
                                        ],
                                        'responderID' => [
                                            'tag' => ASN1::TYPE_OCTET_STRING
                                        ],
                                        'producedAt' => [
                                            'tag' => ASN1::TYPE_GENERALIZED_TIME
                                        ],
                                        'responses' => [
                                            'tag' => ASN1::TYPE_SEQUENCE,
                                            'repeat' => [
                                                'tag' => ASN1::TYPE_SEQUENCE,
                                                'children' => [
                                                    'certID' => [
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
                                                            'issuerNameHash' => [
                                                                'tag' => ASN1::TYPE_OCTET_STRING,
                                                            ],
                                                            'issuerKeyHash' => [
                                                                'tag' => ASN1::TYPE_OCTET_STRING,
                                                            ],
                                                            'serialNumber' => [
                                                                'tag' => ASN1::TYPE_INTEGER,
                                                                'base' => 16
                                                            ]
                                                        ]
                                                    ],
                                                    'certStatus' => [
                                                        'tag' => ASN1::TYPE_CHOICE,
                                                        'children' => [
                                                            'good'    => [ 'tag' => 0, 'value' => 'good' ],
                                                            'revoked' => [ 'tag' => 1, 'value' => 'revoked' ],
                                                            'unknown' => [ 'tag' => 2, 'value' => 'unknown' ],
                                                        ]
                                                    ],
                                                    'thisUpdate' => [ 'tag' => ASN1::TYPE_GENERALIZED_TIME ],
                                                    'nextUpdate' => [
                                                        'tag' => ASN1::TYPE_GENERALIZED_TIME,
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
                                'signature' => [
                                    'tag' => ASN1::TYPE_BIT_STRING,
                                ],
                                'certs' => [
                                    'tag' => ASN1::TYPE_SEQUENCE,
                                    'optional' => true,
                                    'repeat' => [
                                        'tag' => ASN1::TYPE_ANY_SKIP,
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]
    ];

    public static function generateRequest(
        string $algorithm,
        string $issuerNameHash,
        string $issuerKeyHash,
        string $serialNumber,
        string $requestor = null
    ) {
        $src = [
            'tbsRequest' => [
                // 'version' => 'v1',
                // 'requestorName' => 'other:' . ($requestor ?? 'vakata\\ASN1'),
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
        return ASN1::encodeDER($src, static::$request);
    }
    /**
     * Parse an OCSP request
     * @param  string               $data the OCSP request
     * @return array                      the parsed OCSP request
     */
    public static function parseRequest($data)
    {
        return ASN1::decodeDER($data, static::$request);
    }
    /**
     * Parse an OCSP response
     * @param  string               $data the OCSP response
     * @return array                      the parsed OCSP response
     */
    public static function parseResponse($data)
    {
        return ASN1::decodeDER($data, static::$response);
    }
}
