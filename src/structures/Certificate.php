<?php

namespace vakata\asn1\structures;

use \vakata\asn1\ASN1;

/**
 * A class for x509 certificate parsing
 */
class Certificate extends Structure
{
    public static function map()
    {
        return [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'tbsCertificate' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'version' => [
                            'name' => 0,
                            'implicit' => false,
                            'tag' => ASN1::TYPE_INTEGER,
                            'map' => [1=>'v1','v2','v3']
                        ],
                        'serialNumber' => [
                            'tag' => ASN1::TYPE_INTEGER,
                            'base' => 16
                        ],
                        'signature' => Common::AlgorithmIdentifier(),
                        'issuer' => Common::RDNSequence(),
                        'validity' => [
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'notBefore' => [
                                    'tag' => ASN1::TYPE_CHOICE,
                                    'children' => [
                                        [ 'tag' => ASN1::TYPE_GENERALIZED_TIME ],
                                        [ 'tag' => ASN1::TYPE_UTC_TIME ]
                                    ]
                                ],
                                'notAfter' => [
                                    'tag' => ASN1::TYPE_CHOICE,
                                    'children' => [
                                        [ 'tag' => ASN1::TYPE_GENERALIZED_TIME ],
                                        [ 'tag' => ASN1::TYPE_UTC_TIME ]
                                    ]
                                ]
                            ]
                        ],
                        'subject' => Common::RDNSequence(),
                        'SubjectPublicKeyInfo' => [
                            'tag' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'algorithm' => Common::AlgorithmIdentifier(),
                                'publicKey' => [
                                    'tag' => ASN1::TYPE_BIT_STRING
                                ]
                            ]
                        ],
                        'issuerUniqueID' => [
                            'tag' => ASN1::TYPE_BIT_STRING,
                            'name' => 1,
                            'implicit' => true,
                            'optional' => true
                        ],
                        'subjectUniqueID' => [
                            'tag' => ASN1::TYPE_BIT_STRING,
                            'name' => 2,
                            'implicit' => true,
                            'optional' => true
                        ],
                        'extensions' => Common::extensions() + [ 'name' => 3, 'implicit' => false ]
                    ]
                ],
                'signatureAlgorithm' => Common::AlgorithmIdentifier(),
                'signatureValue' => [
                    'tag' => ASN1::TYPE_BIT_STRING,
                ]
            ]
        ];
    }
}
