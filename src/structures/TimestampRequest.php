<?php

namespace vakata\asn1\structures;

use \vakata\asn1\ASN1;
use \vakata\asn1\Encoder;

class TimestampRequest extends Structure
{
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
    public static function generateFromData($data, $nonce = true, $requireCert = false, $alg = 'sha1', $policy = null)
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

        return Encoder::encode($src, static::map());
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
    public static function generateFromHash($data, $nonce = true, $requireCert = false, $alg = 'sha1', $policy = null)
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

        return Encoder::encode($src, static::map());
    }

    public static function map()
    {
        return [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => [
                    'tag' => ASN1::TYPE_INTEGER,
                    'map' => [1=>'v1','v2','v3']
                ],
                'reqPolicy' => [
                    'tag' => ASN1::TYPE_OBJECT_IDENTIFIER,
                    'optional' => true,
                ],
                'messageImprint' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                       'hashAlgorithm' => Common::AlgorithmIdentifier(),
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
    }
}
