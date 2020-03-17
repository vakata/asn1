<?php

namespace vakata\asn1\structures;

use \vakata\asn1\ASN1;

/**
 * A class for OCSP parsing
 */
class OCSPResponse extends Structure
{
    public function subject()
    {
        $map = static::map();
        $map['children']['responseBytes']['children']['response']['map']['children']['tbsResponseData']['tag'] =
            ASN1::TYPE_ANY_DER;
        $temp = \vakata\asn1\Decoder::fromString($this->getReader()->chunk(0))->map($map);
        return $temp['responseBytes']['response']['tbsResponseData'];
    }

    public static function map()
    {
        return [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'responseStatus' => [
                    'tag' => ASN1::TYPE_ENUMERATED,
                    'map' => [
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
                    'name' => 0,
                    'implicit' => false,
                    'optional' => true,
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'responseType' => [
                            'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                        ],
                        'response' => [
                            'tag' => ASN1::TYPE_OCTET_STRING,
                            'der' => true,
                            'map' => [
                                'tag' => ASN1::TYPE_SEQUENCE,
                                'children' => [
                                    'tbsResponseData' => [
                                        'tag' => ASN1::TYPE_SEQUENCE,
                                        'children' => [
                                            'version' => [
                                                'tag' => ASN1::TYPE_INTEGER,
                                                'name' => 0,
                                                'implicit' => false,
                                                'map' => [1=>'v1'],
                                                'optional' => true
                                            ],
                                            'responderID' => [
                                                'tag' => ASN1::TYPE_CHOICE,
                                                'children' => [
                                                    'byName' => [
                                                        'name' => 1,
                                                        'tag' => ASN1::TYPE_OCTET_STRING,
                                                    ],
                                                    'byKey' => [
                                                        'name' => 2,
                                                        'tag' => ASN1::TYPE_OCTET_STRING,
                                                    ]
                                                ]
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
                                                                ]
                                                            ]
                                                        ],
                                                        'certStatus' => [
                                                            'tag' => ASN1::TYPE_CHOICE,
                                                            'children' => [
                                                                'good'    => [
                                                                    'name' => 0,
                                                                    'tag' => 0,
                                                                    'value' => 'good'
                                                                ],
                                                                'revoked' => [
                                                                    'name' => 1,
                                                                    'tag' => 1,
                                                                    'value' => 'revoked'
                                                                ],
                                                                'unknown' => [
                                                                    'name' => 2,
                                                                    'tag' => 2,
                                                                    'value' => 'unknown'
                                                                ],
                                                            ]
                                                        ],
                                                        'thisUpdate' => [ 'tag' => ASN1::TYPE_GENERALIZED_TIME ],
                                                        'nextUpdate' => [
                                                            'tag' => ASN1::TYPE_GENERALIZED_TIME,
                                                            'name' => 0,
                                                            'implicit' => false,
                                                            'optional' => true
                                                        ],
                                                        'extensions' => Common::extensions() + [
                                                            'name' => 1,
                                                            'implicit' => false
                                                        ]
                                                    ]
                                                ]
                                            ],
                                            'extensions' => Common::extensions() + [ 'name' => 1, 'implicit' => false ]
                                        ]
                                    ],
                                    'signatureAlgorithm' => Common::AlgorithmIdentifier(),
                                    'signature' => [
                                        'tag' => ASN1::TYPE_BIT_STRING,
                                    ],
                                    'certs' => [
                                        'tag' => ASN1::TYPE_SEQUENCE,
                                        'name' => 0,
                                        'implicit' => false,
                                        'optional' => true,
                                        'repeat' => [
                                            'tag' => ASN1::TYPE_ANY_DER,
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
}
