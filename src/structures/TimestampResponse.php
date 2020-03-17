<?php

namespace vakata\asn1\structures;

use \vakata\asn1\ASN1;

class TimestampResponse extends Structure
{
    public static function map()
    {
        return [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'status' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'status' => [
                            'tag' => ASN1::TYPE_INTEGER,
                            'map' => [
                                'granted',
                                'grantedWithMods',
                                'rejection',
                                'waiting',
                                'revocationWarning',
                                'revocationNotification'
                            ]
                        ],
                        'statusString' => [
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'data' => [
                                    'tag' =>ASN1::TYPE_UTF8_STRING
                                ]
                            ]
                        ],
                        'failInfo' => [
                            'tag' => ASN1::TYPE_BIT_STRING,
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
                            'name' => 0,
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'version' => ['tag' => ASN1::TYPE_INTEGER ],
                                'algorithms' => [
                                    'tag' => ASN1::TYPE_SET,
                                    'children' => [
                                        'hashAlgorithm' => Common::AlgorithmIdentifier(),
                                    ],
                                ],
                                "tokenInfo" => [
                                    'tag' => ASN1::TYPE_SEQUENCE,
                                    'optional' => true,
                                    'children' => [
                                        'contentType' => ['tag' => ASN1::TYPE_OBJECT_IDENTIFIER ],
                                        'data' => [
                                            'name' => 0,
                                            'tag' => ASN1::TYPE_OCTET_STRING,
                                            'der' => true,
                                            'map' => static::mapToken()
                                        ]
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ];
    }
    public static function mapToken()
    {
        return [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => ['tag' => ASN1::TYPE_INTEGER, 'map' => [1 => 'v1','v2','v3'] ],
                'policy' =>  ['tag' => ASN1::TYPE_OBJECT_IDENTIFIER, 'optional' => true ],
                'messageImprint' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                       'hashAlgorithm' => Common::AlgorithmIdentifier(),
                       'hashedMessage' => [
                            'tag' => ASN1::TYPE_OCTET_STRING
                            //'optional' => true // non-optional
                       ]
                    ]
                ],
                'serialNumber' => ['tag' => ASN1::TYPE_INTEGER, 'base' => 16, 'optional' => true ], // non-optional
                'genTime' => ['tag' => ASN1::TYPE_GENERALIZED_TIME], // GeneralizedTime (non-optional]
                'accuracy' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'optional' => true,
                    'children' => [
                        'seconds' => ['tag' => ASN1::TYPE_INTEGER, 'optional' => true ],
                        'millis' => ['tag' => ASN1::TYPE_INTEGER, 'optional' => true, 'name' => 0, 'implicit' => true ],
                        'micros' => ['tag' => ASN1::TYPE_INTEGER, 'optional' => true, 'name' => 1, 'implicit' => true ],
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
                'tsa' => ['tag' => ASN1::TYPE_ANY_DER, 'optional' => true, 'name' => 0], // [0] GeneralName
                'extensions' => ['tag' => ASN1::TYPE_ANY, 'optional' => true, 'name' => 1] // [0] GeneralName
            ]
        ];
    }
}
