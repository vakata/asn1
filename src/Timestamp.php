<?php

namespace vakata\asn1;

/**
 * A class for timestamp request / response parsing
 */
class Timestamp
{
    protected static $request = [
        'tag' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => [
                'tag' => ASN1::TYPE_INTEGER,
                'mapping' => [1=>'v1','v2','v3']
            ],
            'reqPolicy' => [
                'tag' => ASN1::TYPE_OBJECT_IDENTIFIER,
                'optional' => true
            ],
            'messageImprint' => [
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
                   'hashedMessage' => [
                        'tag' => ASN1::TYPE_OCTET_STRING
                   ]
                ]
            ],
            'nonce' => [
                'tag' => ASN1::TYPE_INTEGER,
                'optional' => true
            ],
            'certReq' => [
                'tag' => ASN1::TYPE_BOOLEAN,
                'optional' => true
            ]
        ]
    ];
    protected static $response = [
        'tag' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'status' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'children' => [
                    'status' => [
                        'tag' => ASN1::TYPE_INTEGER,
                        'mapping' => [
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
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'children' => [
                            'version' => ['tag' => ASN1::TYPE_INTEGER ],
                            'algorithms' => [
                                'tag' => ASN1::TYPE_SET,
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
                                ],
                            ],
                            "tokenInfo" => ['tag' => ASN1::TYPE_ANY_RAW]
                        ]
                    ]
                ]
            ]
        ]
    ];
    protected static $tokenInfo = [
        'tag' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'version' => ['tag' => ASN1::TYPE_INTEGER, 'mapping' => [1 => 'v1','v2','v3'] ],
            'policy' =>  ['tag' => ASN1::TYPE_OBJECT_IDENTIFIER, 'optional' => true ],
            'messageImprint' => [
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
                   'hashedMessage' => [
                        'tag' => ASN1::TYPE_OCTET_STRING,
                        'optional' => true // non-optional
                   ]
                ]
            ],
            'serialNumber' => ['tag' => ASN1::TYPE_INTEGER, 'optional' => true ], // non-optional
            'genTime' => ['tag' => ASN1::TYPE_GENERALIZED_TIME], // GeneralizedTime (non-optional]
            'accuracy' => [
                'tag' => ASN1::TYPE_SEQUENCE,
                'optional' => true,
                'children' => [
                    'seconds' => ['tag' => ASN1::TYPE_ANY, 'optional' => true ],
                    'millis' => ['tag' => ASN1::TYPE_ANY, 'optional' => true ],
                    'micros' => ['tag' => ASN1::TYPE_ANY, 'optional' => true ],
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
            'tsa' => ['tag' => ASN1::TYPE_NULL, 'optional' => true] // [0] GeneralName
        ]
    ];

    /**
     * Generate a timestamp request (tsq) for a file path
     * @param  string           $path        the path to the file to be timestamped
     * @param  boolean|string   $nonce       should a nonce be used - defaults to true, could be a value to use as nonce
     * @param  boolean          $requireCert should a certificate be returned in the response, defaults to false
     * @param  string           $alg         the algorithm to use, defaults to 'sha1'
     * @param  string|null      $policy      the policy to use, defaults to null
     * @return string                        the raw timestamp request
     * @codeCoverageIgnore
     */
    public static function generateRequestFromFile($path, $nonce = true, $requireCert = false, $alg = 'sha1', $policy = null)
    {
        return static::generateRequestFromData(file_get_contents($path), $none, $requireCert, $alg, $policy);
    }
    /**
     * Generate a timestamp request (tsq) for a string
     * @param  string           $data        the data to be timestamped
     * @param  boolean|string   $nonce       should a nonce be used - defaults to true, could be a value to use as nonce
     * @param  boolean          $requireCert should a certificate be returned in the response, defaults to false
     * @param  string           $alg         the algorithm to use, defaults to 'sha1'
     * @param  string|null      $policy      the policy to use, defaults to null
     * @return string                        the raw timestamp request
     */
    public static function generateRequestFromData($data, $nonce = true, $requireCert = false, $alg = 'sha1', $policy = null)
    {
        if (!in_array($alg, ['sha1', 'sha256', 'sha384', 'sha512', 'md5'])) {
            throw new TimestampException('Unsupported hash algorithm');
        }
        $hash = hash($alg, $data, true);
        if ($nonce === true) {
            $nonce = rand(1, PHP_INT_MAX);
        }
        if (!$nonce) {
            $nonce = null;
        }
        
        $src = [
            'version' => 'v1',
            'reqPolicy' => $policy,
            'messageImprint' => [
                'hashAlgorithm' => [ "algorithm" => $alg, 'parameters' => null ],
                'hashedMessage' => base64_encode($hash),
            ],
            'nonce' => $nonce,
            'certReq' => $requireCert
        ];

        return ASN1::encodeDER($src, static::$request);
    }
    /**
     * Generate a timestamp request (tsq) for a given hash
     * @param  string           $data        the hash to be timestamped (raw binary)
     * @param  boolean|string   $nonce       should a nonce be used - defaults to true, could be a value to use as nonce
     * @param  boolean          $requireCert should a certificate be returned in the response, defaults to false
     * @param  string           $alg         the algorithm to use, defaults to 'sha1'
     * @param  string|null      $policy      the policy to use, defaults to null
     * @return string                        the raw timestamp request
     */
    public static function generateRequestFromHash($data, $nonce = true, $requireCert = false, $alg = 'sha1', $policy = null)
    {
        if (!in_array($alg, ['sha1', 'sha256', 'sha384', 'sha512', 'md5'])) {
            throw new TimestampException('Unsupported hash algorithm');
        }
        if ($nonce === true) {
            $nonce = rand(1, PHP_INT_MAX);
        }
        if (!$nonce) {
            $nonce = null;
        }
        
        $src = [
            'version' => 'v1',
            'reqPolicy' => $policy,
            'messageImprint' => [
                'hashAlgorithm' => [ "algorithm" => $alg, 'parameters' => null ],
                'hashedMessage' => base64_encode($data),
            ],
            'nonce' => $nonce,
            'certReq' => $requireCert
        ];

        return ASN1::encodeDER($src, static::$request);
    }
    /**
     * Parse a timestamp request
     * @param  string               $data the request
     * @return array                      the parsed request
     */
    public static function parseRequestFromData($data)
    {
        return ASN1::decodeDER($data, static::$request);
    }
    /**
     * Parse a timestamp request from a file
     * @param  string               $path the path to the timestamp request file
     * @return array                      the parsed request
     * @codeCoverageIgnore
     */
    public static function parseRequestFromFile($path)
    {
        return static::parseRequestFromData(file_get_contents($path));
    }
    /**
     * Parse a timestamp response
     * @param  string               $data the response
     * @return array                      the parsed response
     */
    public static function parseResponseFromData($data)
    {
        $tsr = ASN1::decodeDER($data, static::$response);
        if (in_array($tsr['status']['status'], [ 'granted', 'grantedWithMods']) &&
            isset($tsr['timeStampToken']) &&
            isset($tsr['timeStampToken']["signedData"]) &&
            isset($tsr['timeStampToken']["signedData"]["tokenInfo"]) &&
            isset($tsr['timeStampToken']["signedData"]["tokenInfo"][1])
        ) {
            $tsr['timeStampToken']["signedData"]["tokenInfo"] = ASN1::decodeDER(
                $tsr['timeStampToken']["signedData"]["tokenInfo"][1],
                static::$tokenInfo
            );
        }
        return $tsr;
    }
    /**
     * Parse a timestamp response from a file
     * @param  string               $data the path to the timestamp response file
     * @return array                      the parsed response
     * @codeCoverageIgnore
     */
    public static function parseResponseFromFile($path)
    {
        return static::parseResponseFromData(file_get_contents($path));
    }
}
