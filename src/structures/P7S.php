<?php

namespace vakata\asn1\structures;

use \vakata\asn1\ASN1;

class P7S extends Structure
{
    public static function map()
    {
        return [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'type' => [
                    'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                ],
                'data' => [
                    'name' => 0,
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'implicit' => false,
                    'children' => [
                        'version' => [
                            'tag' => ASN1::TYPE_INTEGER
                        ],
                        'algos' => [
                            'tag' => ASN1::TYPE_SET,
                            'repeat' => Common::AlgorithmIdentifier(),
                        ],
                        'content' =>[
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                "type" => [
                                    'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                                ],
                                'data' => [ 'tag' => ASN1::TYPE_ANY_DER, 'optional' => true ]
                            ]
                        ],
                        'certificates' => [
                            'tag' => ASN1::TYPE_SET,
                            'name' => 0,
                            'implicit' => true,
                            'optional' => true,
                            'repeat' => Certificate::map()
                        ],
                        'crls' => [
                            'tag' => ASN1::TYPE_SET,
                            'name' => 1,
                            'implicit' => true,
                            'optional' => true,
                            'repeat' => [
                                'tag' => ASN1::TYPE_ANY
                            ]
                        ],
                        'signerInfos' => [
                            'tag' => ASN1::TYPE_SET,
                            'repeat' => [
                                'tag' => ASN1::TYPE_SEQUENCE,
                                'children' => [
                                    'version' => [ 'tag' => ASN1::TYPE_INTEGER ],
                                    'sid' => [ 'tag' => ASN1::TYPE_ANY_DER ],
                                    'digest_algo' => Common::AlgorithmIdentifier(),
                                    'signed' => [
                                        'name' => 0,
                                        'tag' => ASN1::TYPE_SET,
                                        'optional' => true,
                                        'implicit' => true,
                                        'repeat' => [
                                            'tag' => ASN1::TYPE_SEQUENCE,
                                            'children' => [
                                                "type" => [
                                                    'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                                                ],
                                                "data" => [
                                                    'tag' => ASN1::TYPE_SET,
                                                    'repeat' => [
                                                        'tag' => ASN1::TYPE_ANY_DER
                                                    ]
                                                ]
                                            ]
                                        ]
                                    ],
                                    'signature_algo' => Common::AlgorithmIdentifier(),
                                    'signature' => [ 'tag' => ASN1::TYPE_OCTET_STRING ],
                                    'unsigned' => [
                                        'name' => 1,
                                        'tag' => ASN1::TYPE_SET,
                                        'optional' => true,
                                        'implicit' => true,
                                        'repeat' => [
                                            'tag' => ASN1::TYPE_SEQUENCE,
                                            'children' => [
                                                "type" => [
                                                    'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                                                ],
                                                "data" => [
                                                    'tag' => ASN1::TYPE_SET,
                                                    'repeat' => [
                                                        'tag' => ASN1::TYPE_ANY_DER
                                                    ]
                                                ]
                                            ]
                                        ]
                                    ],
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ];
    }
}
