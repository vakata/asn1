<?php

namespace vakata\asn1\structures;

use \vakata\asn1\ASN1;

/**
 * A class for CRL parsing
 */
class CRL extends Structure
{
    public static function map()
    {
        return [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'tbsCertList' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'version' => [
                            'tag' => ASN1::TYPE_INTEGER,
                            'map' => [1=>'v1','v2','v3']
                        ],
                        'signature' => Common::AlgorithmIdentifier(),
                        'issuer' => Common::RDNSequence(),
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
                            'optional' => true,
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
                                    'extensions' => Common::extensions()
                                ]
                            ]
                        ],
                        'extensions' => Common::extensions() + [ 'name' => 0, 'implicit' => false ]
                    ]
                ],
                'signatureAlgorithm' => Common::AlgorithmIdentifier(),
                'signatureValue' => [
                    'tag' => ASN1::TYPE_BIT_STRING,
                ]
            ]
        ];
    }
    public function revoked()
    {
        $rd = $this->data->getReader();
        $ld = new \vakata\asn1\LazyDecoder($rd);
        $mp = static::map();
        foreach ($ld->lazyMap($mp)['tbsCertList']['revokedCertificates']->rawData() as $v) {
            yield \vakata\asn1\Decoder::fromString($rd->chunk($v['start'], $v['length']))
                ->map($mp['children']['tbsCertList']['children']['revokedCertificates']['repeat']);
        }
    }
}
