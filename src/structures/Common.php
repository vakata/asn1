<?php

namespace vakata\asn1\structures;

use \vakata\asn1\ASN1;

class Common
{
    public static function AlgorithmIdentifier()
    {
        return [
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
        ];
    }
    public static function RDNSequence()
    {
        return [
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
        ];
    }
    public static function extensions()
    {
        return [
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
        ];
    }
}
