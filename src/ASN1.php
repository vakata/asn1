<?php
/* Based on PHPSECLIB: https://github.com/phpseclib/phpseclib/blob/master/phpseclib/File/ASN1.php */

namespace vakata\asn1;

use DateTime;

/**
 * A class handling ASN1 encoding / decoding.
 */
class ASN1
{
    const CLASS_UNIVERSAL        = 0;
    const CLASS_APPLICATION      = 1;
    const CLASS_CONTEXT_SPECIFIC = 2;
    const CLASS_PRIVATE          = 3;

    const TYPE_BOOLEAN           = 1;
    const TYPE_INTEGER           = 2;
    const TYPE_BIT_STRING        = 3;
    const TYPE_OCTET_STRING      = 4;
    const TYPE_NULL              = 5;
    const TYPE_OBJECT_IDENTIFIER = 6;
    const TYPE_OBJECT_DESCRIPTOR = 7;
    const TYPE_INSTANCE_OF       = 8; // EXTERNAL
    const TYPE_REAL              = 9;
    const TYPE_ENUMERATED        = 10;
    const TYPE_EMBEDDED          = 11;
    const TYPE_UTF8_STRING       = 12;
    const TYPE_RELATIVE_OID      = 13;
    const TYPE_SEQUENCE          = 16; // SEQUENCE OF
    const TYPE_SET               = 17; // SET OF
    const TYPE_NUMERIC_STRING    = 18;
    const TYPE_PRINTABLE_STRING  = 19;
    const TYPE_TELETEX_STRING    = 20; // T61String
    const TYPE_VIDEOTEX_STRING   = 21;
    const TYPE_IA5_STRING        = 22;
    const TYPE_UTC_TIME          = 23;
    const TYPE_GENERALIZED_TIME  = 24;
    const TYPE_GRAPHIC_STRING    = 25;
    const TYPE_VISIBLE_STRING    = 26; // ISO646String
    const TYPE_GENERAL_STRING    = 27;
    const TYPE_UNIVERSAL_STRING  = 28;
    const TYPE_CHARACTER_STRING  = 29;
    const TYPE_BMP_STRING        = 30;
    const TYPE_CHOICE            = -1;
    const TYPE_ANY               = -2;
    const TYPE_ANY_RAW           = -3;

    public static $oids = [
        'sha1' =>                 '1.3.14.3.2.26',
        'sha256' =>               '2.16.840.1.101.3.4.2.1',
        'sha384' =>               '2.16.840.1.101.3.4.2.2',
        'sha512' =>               '2.16.840.1.101.3.4.2.3',
        'sha224' =>               '2.16.840.1.101.3.4.2.4',
        'md5' =>                  '1.2.840.113549.2.5',
        'md2' =>                  '1.3.14.7.2.2.1',
        'ripemd160' =>            '1.3.36.3.2.1',
        'MD2withRSA' =>           '1.2.840.113549.1.1.2',
        'MD4withRSA' =>           '1.2.840.113549.1.1.3',
        'MD5withRSA' =>           '1.2.840.113549.1.1.4',
        'SHA1withRSA' =>          '1.2.840.113549.1.1.5',
        'SHA224withRSA' =>        '1.2.840.113549.1.1.14',
        'SHA256withRSA' =>        '1.2.840.113549.1.1.11',
        'SHA384withRSA' =>        '1.2.840.113549.1.1.12',
        'SHA512withRSA' =>        '1.2.840.113549.1.1.13',
        'SHA1withECDSA' =>        '1.2.840.10045.4.1',
        'SHA224withECDSA' =>      '1.2.840.10045.4.3.1',
        'SHA256withECDSA' =>      '1.2.840.10045.4.3.2',
        'SHA384withECDSA' =>      '1.2.840.10045.4.3.3',
        'SHA512withECDSA' =>      '1.2.840.10045.4.3.4',
        'dsa' =>                  '1.2.840.10040.4.1',
        'SHA1withDSA' =>          '1.2.840.10040.4.3',
        'SHA224withDSA' =>        '2.16.840.1.101.3.4.3.1',
        'SHA256withDSA' =>        '2.16.840.1.101.3.4.3.2',
        'rsaEncryption' =>        '1.2.840.113549.1.1.1',
        'countryName' =>          '2.5.4.6',
        'organization' =>         '2.5.4.10',
        'organizationalUnit' =>   '2.5.4.11',
        'stateOrProvinceName' =>  '2.5.4.8',
        'locality' =>             '2.5.4.7',
        'commonName' =>           '2.5.4.3',
        'subjectKeyIdentifier' => '2.5.29.14',
        'keyUsage' =>             '2.5.29.15',
        'subjectAltName' =>       '2.5.29.17',
        'basicConstraints' =>     '2.5.29.19',
        'nameConstraints' =>      '2.5.29.30',
        'cRLDistributionPoints' =>'2.5.29.31',
        'certificatePolicies' =>  '2.5.29.32',
        'authorityKeyIdentifier'=>'2.5.29.35',
        'policyConstraints' =>    '2.5.29.36',
        'extKeyUsage' =>          '2.5.29.37',
        'authorityInfoAccess' =>  '1.3.6.1.5.5.7.1.1',
        'anyExtendedKeyUsage' =>  '2.5.29.37.0',
        'serverAuth' =>           '1.3.6.1.5.5.7.3.1',
        'clientAuth' =>           '1.3.6.1.5.5.7.3.2',
        'codeSigning' =>          '1.3.6.1.5.5.7.3.3',
        'emailProtection' =>      '1.3.6.1.5.5.7.3.4',
        'timeStamping' =>         '1.3.6.1.5.5.7.3.8',
        'ocspSigning' =>          '1.3.6.1.5.5.7.3.9',
        'ecPublicKey' =>          '1.2.840.10045.2.1',
        'secp256r1' =>            '1.2.840.10045.3.1.7',
        'secp256k1' =>            '1.3.132.0.10',
        'secp384r1' =>            '1.3.132.0.34',
        'pkcs5PBES2' =>           '1.2.840.113549.1.5.13',
        'pkcs5PBKDF2' =>          '1.2.840.113549.1.5.12',
        'des-EDE3-CBC' =>         '1.2.840.113549.3.7',
        'data' =>                 '1.2.840.113549.1.7.1', // CMS data
        'signed-data' =>          '1.2.840.113549.1.7.2', // CMS signed-data
        'enveloped-data' =>       '1.2.840.113549.1.7.3', // CMS enveloped-data
        'digested-data' =>        '1.2.840.113549.1.7.5', // CMS digested-data
        'encrypted-data' =>       '1.2.840.113549.1.7.6', // CMS encrypted-data
        'authenticated-data' =>   '1.2.840.113549.1.9.16.1.2', // CMS authenticated-data
        'tstinfo' =>              '1.2.840.113549.1.9.16.1.4', // RFC3161 TSTInfo,
        'pkix' => '1.3.6.1.5.5.7',
        'pe' => '1.3.6.1.5.5.7.1',
        'qt' => '1.3.6.1.5.5.7.2',
        'kp' => '1.3.6.1.5.5.7.3',
        'ad' => '1.3.6.1.5.5.7.48',
        'cps' => '1.3.6.1.5.5.7.2.1',
        'unotice' => '1.3.6.1.5.5.7.2.2',
        'ocsp' =>'a1.3.6.1.5.5.7.48.1',
        'caIssuers' => '1.3.6.1.5.5.7.48.2',
        'timeStamping' => '1.3.6.1.5.5.7.48.3',
        'caRepository' => '1.3.6.1.5.5.7.48.5',
        'at' => '2.5.4',
        'name' => '2.5.4.41',
        'surname' => '2.5.4.4',
        'givenName' => '2.5.4.42',
        'initials' => '2.5.4.43',
        'generationQualifier' => '2.5.4.44',
        'commonName' => '2.5.4.3',
        'localityName' => '2.5.4.7',
        'stateOrProvinceName' => '2.5.4.8',
        'organizationName' => '2.5.4.10',
        'organizationalUnitName' => '2.5.4.11',
        'title' => '2.5.4.12',
        'description' => '2.5.4.13',
        'dnQualifier' => '2.5.4.46',
        'countryName' => '2.5.4.6',
        'serialNumber' => '2.5.4.5',
        'pseudonym' => '2.5.4.65',
        'postalCode' => '2.5.4.17',
        'streetAddress' => '2.5.4.9',
        'uniqueIdentifier' => '2.5.4.45',
        'role' => '2.5.4.72',
        'postalAddress' => '2.5.4.16',
        'domainComponent' => '0.9.2342.19200300.100.1.25',
        'pkcs-9' => '1.2.840.113549.1.9',
        'emailAddress' => '1.2.840.113549.1.9.1',
        'ce' => '2.5.29',
        'authorityKeyIdentifier' => '2.5.29.35',
        'subjectKeyIdentifier' => '2.5.29.14',
        'keyUsage' => '2.5.29.15',
        'privateKeyUsagePeriod' => '2.5.29.16',
        'certificatePolicies' => '2.5.29.32',
        'anyPolicy' => '2.5.29.32.0',
        'policyMappings' => '2.5.29.33',
        'subjectAltName' => '2.5.29.17',
        'issuerAltName' => '2.5.29.18',
        'subjectDirectoryAttributes' => '2.5.29.9',
        'basicConstraints' => '2.5.29.19',
        'nameConstraints' => '2.5.29.30',
        'policyConstraints' => '2.5.29.36',
        'cRLDistributionPoints' => '2.5.29.31',
        'extKeyUsage' => '2.5.29.37',
        'anyExtendedKeyUsage' => '2.5.29.37.0',
        'kp-serverAuth' => '1.3.6.1.5.5.7.3.1',
        'kp-clientAuth' => '1.3.6.1.5.5.7.3.2',
        'kp-codeSigning' => '1.3.6.1.5.5.7.3.3',
        'kp-emailProtection' => '1.3.6.1.5.5.7.3.4',
        'kp-timeStamping' => '1.3.6.1.5.5.7.3.8',
        'kp-OCSPSigning' => '1.3.6.1.5.5.7.3.9',
        'inhibitAnyPolicy' => '2.5.29.54',
        'freshestCRL' => '2.5.29.46',
        'pe-authorityInfoAccess' => '1.3.6.1.5.5.7.1.1',
        'pe-subjectInfoAccess' => '1.3.6.1.5.5.7.1.11',
        'cRLNumber' => '2.5.29.20',
        'issuingDistributionPoint' => '2.5.29.28',
        'deltaCRLIndicator' => '2.5.29.27',
        'cRLReasons' => '2.5.29.21',
        'certificateIssuer' => '2.5.29.29',
        'holdInstructionCode' => '2.5.29.23',
        'holdInstruction' => '1.2.840.10040.2',
        'holdinstruction-none' => '1.2.840.10040.2.1',
        'holdinstruction-callissuer' => '1.2.840.10040.2.2',
        'holdinstruction-reject' => '1.2.840.10040.2.3',
        'invalidityDate' => '2.5.29.24',
        'md2' => '1.2.840.113549.2.2',
        'md5' => '1.2.840.113549.2.5',
        'sha1' => '1.3.14.3.2.26',
        'dsa' => '1.2.840.10040.4.1',
        'dsa-with-sha1' => '1.2.840.10040.4.3',
        'pkcs-1' => '1.2.840.113549.1.1',
        'rsaEncryption' => '1.2.840.113549.1.1.1',
        'md2WithRSAEncryption' => '1.2.840.113549.1.1.2',
        'md5WithRSAEncryption' => '1.2.840.113549.1.1.4',
        'sha1WithRSAEncryption' => '1.2.840.113549.1.1.5',
        'dhpublicnumber' => '1.2.840.10046.2.1',
        'keyExchangeAlgorithm' => '2.16.840.1.101.2.1.1.22',
        'ansi-X9-62' => '1.2.840.10045',
        'ecSigType' => '1.2.840.10045.4',
        'ecdsa-with-SHA1' => '1.2.840.10045.4.1',
        'fieldType' => '1.2.840.10045.1',
        'prime-field' => '1.2.840.10045.1.1',
        'characteristic-two-field' => '1.2.840.10045.1.2',
        'characteristic-two-basis' => '1.2.840.10045.1.2.3',
        'gnBasis' => '1.2.840.10045.1.2.3.1',
        'tpBasis' => '1.2.840.10045.1.2.3.2',
        'ppBasis' => '1.2.840.10045.1.2.3.3',
        'publicKeyType' => '1.2.840.10045.2',
        'ecPublicKey' => '1.2.840.10045.2.1',
        'ellipticCurve' => '1.2.840.10045.3',
        'c-TwoCurve' => '1.2.840.10045.3.0',
        'c2pnb163v1' => '1.2.840.10045.3.0.1',
        'c2pnb163v2' => '1.2.840.10045.3.0.2',
        'c2pnb163v3' => '1.2.840.10045.3.0.3',
        'c2pnb176w1' => '1.2.840.10045.3.0.4',
        'c2pnb191v1' => '1.2.840.10045.3.0.5',
        'c2pnb191v2' => '1.2.840.10045.3.0.6',
        'c2pnb191v3' => '1.2.840.10045.3.0.7',
        'c2pnb191v4' => '1.2.840.10045.3.0.8',
        'c2pnb191v5' => '1.2.840.10045.3.0.9',
        'c2pnb208w1' => '1.2.840.10045.3.0.10',
        'c2pnb239v1' => '1.2.840.10045.3.0.11',
        'c2pnb239v2' => '1.2.840.10045.3.0.12',
        'c2pnb239v3' => '1.2.840.10045.3.0.13',
        'c2pnb239v4' => '1.2.840.10045.3.0.14',
        'c2pnb239v5' => '1.2.840.10045.3.0.15',
        'c2pnb272w1' => '1.2.840.10045.3.0.16',
        'c2pnb304w1' => '1.2.840.10045.3.0.17',
        'c2pnb359v1' => '1.2.840.10045.3.0.18',
        'c2pnb368w1' => '1.2.840.10045.3.0.19',
        'c2pnb431r1' => '1.2.840.10045.3.0.20',
        'primeCurve' => '1.2.840.10045.3.1',
        'prime192v1' => '1.2.840.10045.3.1.1',
        'prime192v2' => '1.2.840.10045.3.1.2',
        'prime192v3' => '1.2.840.10045.3.1.3',
        'prime239v1' => '1.2.840.10045.3.1.4',
        'prime239v2' => '1.2.840.10045.3.1.5',
        'prime239v3' => '1.2.840.10045.3.1.6',
        'prime256v1' => '1.2.840.10045.3.1.7',
        'RSAES-OAEP' => '1.2.840.113549.1.1.7',
        'pSpecified' => '1.2.840.113549.1.1.9',
        'RSASSA-PSS' => '1.2.840.113549.1.1.10',
        'mgf1' => '1.2.840.113549.1.1.8',
        'sha224WithRSAEncryption' => '1.2.840.113549.1.1.14',
        'sha256WithRSAEncryption' => '1.2.840.113549.1.1.11',
        'sha384WithRSAEncryption' => '1.2.840.113549.1.1.12',
        'sha512WithRSAEncryption' => '1.2.840.113549.1.1.13',
        'sha224' => '2.16.840.1.101.3.4.2.4',
        'sha256' => '2.16.840.1.101.3.4.2.1',
        'sha384' => '2.16.840.1.101.3.4.2.2',
        'sha512' => '2.16.840.1.101.3.4.2.3',
        'GostR3411-94-with-GostR3410-94' => '1.2.643.2.2.4',
        'GostR3411-94-with-GostR3410-2001' => '1.2.643.2.2.3',
        'GostR3410-2001' => '1.2.643.2.2.20',
        'GostR3410-94' => '1.2.643.2.2.19',
        'netscape' => '2.16.840.1.113730',
        'netscape-cert-extension' => '2.16.840.1.113730.1',
        'netscape-cert-type' => '2.16.840.1.113730.1.1',
        'netscape-comment' => '2.16.840.1.113730.1.13',
        'netscape-ca-policy-url' => '2.16.840.1.113730.1.8',
        'logotype' => '1.3.6.1.5.5.7.1.12',
        'entrustVersInfo' => '1.2.840.113533.7.65.0',
        'verisignPrivate' => '2.16.840.1.113733.1.6.9',
        'unstructuredName' => '1.2.840.113549.1.9.2',
        'challengePassword' => '1.2.840.113549.1.9.7',
        'extensionRequest' => '1.2.840.113549.1.9.14',
        'userid' => '0.9.2342.19200300.100.1.1',
        's/mime' => '1.2.840.113549.1.9.15',
        'unstructuredAddress' => '1.2.840.113549.1.9.8',
        'rc2-cbc' => '1.2.840.113549.3.2',
        'rc4' => '1.2.840.113549.3.4',
        'desCBC' => '1.3.14.3.2.7',
        'qcStatements' => '1.3.6.1.5.5.7.1.3',
        'pkixQCSyntax-v1' => '1.3.6.1.5.5.7.11.1',
        'pkixQCSyntax-v2' => '1.3.6.1.5.5.7.11.2',
        'ipsecEndSystem' => '1.3.6.1.5.5.7.3.5',
        'ipsecTunnel' => '1.3.6.1.5.5.7.3.6',
        'ipsecUser' => '1.3.6.1.5.5.7.3.7',
        'OCSP' => '1.3.6.1.5.5.7.48.1',
        'countryOfCitizenship' => '1.3.6.1.5.5.7.9.4',
        'IPSECProtection' => '1.3.6.1.5.5.8.2.2',
        'telephoneNumber' => '2.5.4.20',
        'organizationIdentifier' => '2.5.4.97'
    ];

    /**
     * Convert a number to base256
     * @param  integer    $number the number to convert
     * @param  integer    $base   the current base of the number (optional, defaults to 10)
     * @return string             the number in base256
     */
    public static function toBase256($number, $base = 10)
    {
        $bin = base_convert($number, $base, 2);
        $res = "";
        $len = ceil(strlen($bin) / 8) * 8;
        $bin = str_pad($bin, $len, "0", STR_PAD_LEFT);
        for ($i = ($len-8); $i >= 0; $i -= 8) {
            $res = chr(base_convert(substr($bin, $i, 8), 2, 10)) . $res;
        }
        return $res;
    }
    /**
     * Convert a number from base256
     * @param  string      $string the number to convert
     * @param  integer     $base   the base to convert to (optional, defaults to 10)
     * @return integer             the converted number
     */
    public static function fromBase256($string, $base = 10)
    {
        $number = "";
        for ($i = 0; $i < strlen($string); $i++) {
            $number .= str_pad(base_convert(ord($string{$i}), 10, 2), 8, "0", STR_PAD_LEFT);
        }
        return $number;
    }

    /**
     * Encode some data to DER using a mapping array.
     * @param  mixed     $source  the data to convert
     * @param  array     $mapping rules to convert by (check the example on https://gihub.com/vakata/asn1)
     * @return string             raw DER output (base64_encode if needed)
     */
    public static function encodeDER($source, $mapping)
    {
        if (isset($mapping['default']) && $source === $mapping['default']) {
            return '';
        }

        $tag = $mapping['tag'];
        switch ($tag) {
            case static::TYPE_SET:
            case static::TYPE_SEQUENCE:
                $tag |= 0x20; // set the constructed bit
                $value = '';
                if (isset($mapping['min']) && isset($mapping['max'])) {
                    $child = $mapping['children'];
                    foreach ($source as $content) {
                        $temp = static::encodeDER($content, $child);
                        if ($temp === false) {
                            return false;
                        }
                        $value .= $temp;
                    }
                    break;
                }

                foreach ($mapping['children'] as $key => $child) {
                    if (!array_key_exists($key, $source)) {
                        if (!isset($child['optional'])) {
                            return false;
                        }
                        continue;
                    }
                    $temp = static::encodeDER($source[$key], $child);
                    if ($temp === false) {
                        return false;
                    }
                    if ($temp === '') {
                        continue;
                    }
                    $value .= $temp;
                }
                break;
            case static::TYPE_CHOICE:
                $temp = false;
                foreach ($mapping['children'] as $key => $child) {
                    if (!isset($source[$key])) {
                        continue;
                    }
                    $temp = static::encodeDER($source[$key], $child);
                    if ($temp === false) {
                        return false;
                    }
                    if ($temp === '') {
                        continue;
                    }
                    $tag = ord($temp[0]);
                }
                return $temp;
            case static::TYPE_INTEGER:
            case static::TYPE_ENUMERATED:
                if (!isset($mapping['mapping'])) {
                    $value = static::toBase256((int)$source);
                } else {
                    $value = array_search($source, $mapping['mapping']);
                    if ($value === false) {
                        return false;
                    }
                    $value = static::toBase256((int)$value);
                }
                if (!strlen($value)) {
                    $value = chr(0);
                }
                break;
            case static::TYPE_UTC_TIME:
            case static::TYPE_GENERALIZED_TIME:
                $format = $mapping['tag'] == static::TYPE_UTC_TIME ? 'y' : 'Y';
                $format.= 'mdHis';
                $value = @gmdate($format, strtotime($source)) . 'Z';
                break;
            case static::TYPE_BIT_STRING:
                if (isset($mapping['mapping'])) {
                    $bits = array_fill(0, count($mapping['mapping']), 0);
                    $size = 0;
                    for ($i = 0; $i < count($mapping['mapping']); $i++) {
                        if (in_array($mapping['mapping'][$i], $source)) {
                            $bits[$i] = 1;
                            $size = $i;
                        }
                    }

                    if (isset($mapping['min']) && $mapping['min'] >= 1 && $size < $mapping['min']) {
                        $size = $mapping['min'] - 1;
                    }

                    $offset = 8 - (($size + 1) & 7);
                    $offset = $offset !== 8 ? $offset : 0;

                    $value = chr($offset);

                    for ($i = $size + 1; $i < count($mapping['mapping']); $i++) {
                        unset($bits[$i]);
                    }

                    $bits = implode('', array_pad($bits, $size + $offset + 1, 0));
                    $bytes = explode(' ', rtrim(chunk_split($bits, 8, ' ')));
                    foreach ($bytes as $byte) {
                        $value.= chr(bindec($byte));
                    }

                    break;
                }
                // default to octet string if no mapping is present
            case static::TYPE_OCTET_STRING:
                $value = isset($mapping['raw']) && $mapping['raw'] ? $source : base64_decode($source);
                break;
            case static::TYPE_OBJECT_IDENTIFIER:
                if (!isset($source) && $mapping['optional']) {
                    return;
                }
                $oid = preg_match('#(?:\d+\.)+#', $source) ?
                  $source :
                  isset(static::$oids[$source]) ? static::$oids[$source] : false;
                if ($oid === false) {
                    throw new ASN1Exception('Invalid OID');
                }
                $value = '';
                $parts = explode('.', $oid);
                $value = chr(40 * $parts[0] + $parts[1]);
                for ($i = 2; $i < count($parts); $i++) {
                    $temp = '';
                    if (!$parts[$i]) {
                        $temp = "\0";
                    } else {
                        while ($parts[$i]) {
                            $temp = chr(0x80 | ($parts[$i] & 0x7F)) . $temp;
                            $parts[$i] >>= 7;
                        }
                        $temp[strlen($temp) - 1] = $temp[strlen($temp) - 1] & chr(0x7F);
                    }
                    $value.= $temp;
                }
                break;
            case static::TYPE_ANY:
                switch (true) {
                    case !isset($source):
                        return static::encodeDER(null, array('tag' => static::TYPE_NULL) + $mapping);
                    case is_int($source):
                        return static::encodeDER($source, array('tag' => static::TYPE_INTEGER) + $mapping);
                    case is_float($source):
                        return static::encodeDER($source, array('tag' => static::TYPE_REAL) + $mapping);
                    case is_bool($source):
                        return static::encodeDER($source, array('tag' => static::TYPE_BOOLEAN) + $mapping);
                    default:
                        throw new ASN1Exception('Unrecognized type');
                }
                break;
            case static::TYPE_NULL:
                $value = '';
                break;
            case static::TYPE_NUMERIC_STRING:
            case static::TYPE_TELETEX_STRING:
            case static::TYPE_PRINTABLE_STRING:
            case static::TYPE_UNIVERSAL_STRING:
            case static::TYPE_UTF8_STRING:
            case static::TYPE_BMP_STRING:
            case static::TYPE_IA5_STRING:
            case static::TYPE_VISIBLE_STRING:
            case static::TYPE_VIDEOTEX_STRING:
            case static::TYPE_GRAPHIC_STRING:
            case static::TYPE_GENERAL_STRING:
                $value = $source;
                break;
            case static::TYPE_BOOLEAN:
                $value = $source ? "\xFF" : "\x00";
                break;
            default:
                throw new ASN1Exception('Mapping provides no type definition');
        }

        return chr($tag) . static::encodeLength(strlen($value)) . $value;
    }

    protected static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }
        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     * Decode DER formatted data.
     * @param  string     $encoded raw DER input
     * @param  array|null $mapping optional mapping to follow (check the example on https://gihub.com/vakata/asn1)
     * @return array               the decoded object
     */
    public static function decodeDER($encoded, array $mapping = null)
    {
        $decoded = static::decode($encoded);
        if (count($decoded) === 1) {
            $decoded = $decoded[0];
        }
        $result = null;
        if ($mapping) {
            static::map($decoded, $mapping, $result);
        } else {
            static::values($decoded, $result);
        }
        return $result;
    }

    protected static function decode($stream)
    {
        if (is_string($stream)) {
            $temp = $stream;
            $stream = fopen('php://temp', 'r+');
            fwrite($stream, $temp);
            rewind($stream);
        }
        $result = [];
        while (!feof($stream)) {
            $identifier = ord(fread($stream, 1));
            $constructed = ($identifier >> 5) & 1; // 6th bit
            $class = ($identifier >> 6) & 3; // 7th and 8th bits
            $tag = $identifier & 31; // first 5 bits

            if ($tag === 31) { // long tag (read each 7 bits until the 8th is 0)
                $tag = 0;
                while (true) {
                    $temp = ord(fread($stream, 1));
                    $tag <<= 7;
                    $tag |= $temp & 127;
                    if (($temp & 128) === 0) {
                        break;
                    }
                }
            }

            $temp = ord(fread($stream, 1));
            $length = null;
            if ($temp === 128) {
                // indefinite
                $length = null;
            } elseif ($temp & 128) {
                // long form
                $octets = $temp & 127;
                $length = 0;
                for ($i = 0; $i < $octets; $i++) {
                    $length <<= 8;
                    $length |= ord(fread($stream, 1));
                }
            } else {
                // short form
                $length = $temp;
            }

            $contents = '';
            if ($length === null) {
                while (!feof($stream)) {
                    $oct1 = fread($stream, 1);
                    $oct2 = fread($stream, 1);
                    if (ord($oct1) === 0 && ord($oct2) === 0) {
                        break;
                    }
                    $contents .= $oct1 . $oct2;
                }
                $length = strlen($contents);
            } else {
                if ($length) {
                    $contents = fread($stream, $length);
                }
            }

            if ($class !== static::CLASS_UNIVERSAL) {
                if ($constructed) {
                    $contents = static::decode($contents);
                    if (count($contents) === 1) {
                        $contents = $contents[0];
                    }
                }
            } else {
                switch ($tag) {
                    case static::TYPE_BOOLEAN:
                        $contents = (bool)ord($contents[0]);
                        break;
                    case static::TYPE_INTEGER:
                        $contents = static::fromBase256($contents);
                        break;
                    case static::TYPE_ENUMERATED:
                        $contents = (int)base_convert(static::fromBase256($contents), 2, 10);
                        break;
                    case static::TYPE_REAL:
                        // TODO: read the specs
                        return false;
                    case static::TYPE_BIT_STRING:
                        if ($constructed) {
                            $temp = static::decode($contents);
                            $real = '';
                            for ($i = 0; $i < count($temp) - 1; $i++) {
                                $real .= $temp['contents'];
                            }
                            $real = $temp[count($temp) - 1]['content'][0] . $real . substr($temp[$i]['content'], 1);
                            $contents = $real;
                        }
                        break;
                    case static::TYPE_OCTET_STRING:
                        if ($constructed) {
                            $contents = implode('', array_map(function ($v) {
                                return $v['contents'];
                            }, static::decode($contents)));
                        }
                        break;
                    case static::TYPE_NULL:
                        $contents = null;
                        break;
                    case static::TYPE_SEQUENCE:
                    case static::TYPE_SET:
                        $contents = static::decode($contents);
                        break;
                    case static::TYPE_OBJECT_IDENTIFIER:
                        $real = '';
                        $temp = ord($contents[0]);
                        $real = sprintf('%d.%d', floor($temp / 40), $temp % 40);
                        $obid = 0;
                        // process septets
                        for ($i = 1; $i < strlen($contents); $i++) {
                            $temp = ord($contents[$i]);
                            $obid <<= 7;
                            $obid |= $temp & 0x7F;
                            if (~$temp & 0x80) {
                                $real .= '.' . $obid;
                                $obid = 0;
                            }
                        }
                        $contents = $real;
                        break;
                    case static::TYPE_UTC_TIME:
                    case static::TYPE_GENERALIZED_TIME:
                    case static::TYPE_NUMERIC_STRING:
                    case static::TYPE_PRINTABLE_STRING:
                    case static::TYPE_TELETEX_STRING:
                    case static::TYPE_VIDEOTEX_STRING:
                    case static::TYPE_VISIBLE_STRING:
                    case static::TYPE_IA5_STRING:
                    case static::TYPE_GRAPHIC_STRING:
                    case static::TYPE_GENERAL_STRING:
                    case static::TYPE_UTF8_STRING:
                    case static::TYPE_BMP_STRING:
                    default:
                        break;
                }
            }
            if ($class > 0 || $tag > 0) {
                $result[] = [
                    'class'    => $class,
                    'tag'      => $tag,
                    'length'   => $length,
                    'contents' => $contents
                ];
            }
        }

        return $result;
    }

    protected static function map($decoded, $mapping, &$result)
    {
        while ($decoded['class'] !== 0 && isset($decoded['contents']) && is_array($decoded['contents'])) {
            $decoded = $decoded['contents'];
        }
        if ($mapping['tag'] === ASN1::TYPE_CHOICE) {
            foreach ($mapping['children'] as $child) {
                if ($decoded['tag'] === $child['tag']) {
                    $mapping = $child;
                    break;
                }
            }
        }
        if (in_array($mapping['tag'], [ASN1::TYPE_SEQUENCE, ASN1::TYPE_SET]) &&
            in_array($decoded['tag'], [ASN1::TYPE_SEQUENCE, ASN1::TYPE_SET])) {
            $mapping['tag'] = $decoded['tag'];
        }
        if (!in_array($mapping['tag'], [ASN1::TYPE_ANY, ASN1::TYPE_ANY_RAW]) && $mapping['tag'] !== $decoded['tag']) {
            if (!isset($mapping['optional']) || !$mapping['optional']) {
                throw new ASN1Exception('Decoded data does not match mapping');
            }
            return false;
        }
        if ($mapping['tag'] === ASN1::TYPE_ANY && isset($decoded['tag'])) {
            $mapping['tag'] = $decoded['tag'];
        }
        switch ($mapping['tag']) {
            case static::TYPE_ANY_RAW:
                static::values($decoded, $result);
                break;
            case static::TYPE_SET:
                if (isset($mapping['repeat'])) {
                    foreach ($decoded['contents'] as $i => $v) {
                        static::map(
                            isset($decoded['contents'][$i]) ? $decoded['contents'][$i] : null,
                            $mapping['repeat'],
                            $result[$i]
                        );
                    }
                } else {
                    $temp = $decoded['contents'];
                    foreach ($mapping['children'] as $k => $v) {
                        $result[$k] = null;
                        foreach ($temp as $kk => $vv) {
                            if ($v['tag'] === ASN1::TYPE_ANY || $v['tag'] === $vv['tag']) {
                                if (static::map($vv, $v, $result[$k])) {
                                    unset($temp[$kk]);
                                } else {
                                    $result[$k] = null;
                                }
                                break;
                            }
                        }
                        if ($result[$k] === null && (!isset($v['optional']) || !$v['optional'])) {
                            throw new ASN1Exception('Decoded data does not match mapping');
                        }
                    }
                }
                break;
            case static::TYPE_SEQUENCE:
                $result = [];
                $i = 0;
                if (isset($mapping['repeat'])) {
                    foreach ($decoded['contents'] as $i => $v) {
                        static::map(
                            isset($decoded['contents'][$i]) ? $decoded['contents'][$i] : null,
                            $mapping['repeat'],
                            $result[$i]
                        );
                    }
                } else {
                    foreach ($mapping['children'] as $k => $v) {
                        $result[$k] = null;
                        if (static::map(
                                isset($decoded['contents'][$i]) ? $decoded['contents'][$i] : null,
                                $v,
                                $result[$k]
                        )) {
                            $i++;
                        }
                    }
                }
                break;
            case static::TYPE_OBJECT_IDENTIFIER:
                $result = array_search($decoded['contents'], static::$oids);
                if ($result === false) {
                    $result = $decoded['contents'];
                }
                break;
            case static::TYPE_OCTET_STRING:
                if (isset($mapping['der']) && $mapping['der']) {
                    $result = static::decodeDER($decoded['contents']);
                } else {
                    $result = base64_encode($decoded['contents']);
                }
                break;
            case static::TYPE_INTEGER:
                $base = isset($mapping['base']) && (int)$mapping['base'] ? (int)$mapping['base'] : 10;
                if ($base < 3) {
                    $result = $decoded['contents'];
                } else {
                    if (strlen($decoded['contents']) > 53 && $base === 16) {
                        $hex = '';
                        for ($i = strlen($decoded['contents']) - 4; $i >= 0; $i-=4) {
                            $hex .= dechex(bindec(substr($decoded['contents'], $i, 4)));
                        }
                        $result = strrev($hex);
                    } else {
                        $temp = base_convert($decoded['contents'], 2, $base);
                        if ($base === 10) {
                            $temp = (int)$temp;
                        }
                        $result = $temp;
                    }
                }
                if (isset($mapping['mapping']) && isset($mapping['mapping'][$result])) {
                    $result = $mapping['mapping'][$result];
                }
                break;
            case static::TYPE_UTC_TIME:
                $content = $decoded['contents'];
                $format = 'YmdHis';
                $matches = [];
                if (preg_match('#^(\d{10})(Z|[+-]\d{4})$#', $content, $matches)) {
                    $content = $matches[1] . '00' . $matches[2];
                }
                $prefix = substr($content, 0, 2) >= 50 ? '19' : '20';
                $content = $prefix . $content;
                if ($content[strlen($content) - 1] == 'Z') {
                    $content = substr($content, 0, -1) . '+0000';
                }
                if (strpos($content, '-') !== false || strpos($content, '+') !== false) {
                    $format.= 'O';
                }
                $result = @DateTime::createFromFormat($format, $content);
                $result = $result ? $result->getTimestamp() : false;
                break;
            case static::TYPE_GENERALIZED_TIME:
                $content = $decoded['contents'];
                $format = 'YmdHis';
                if (strpos($content, '.') !== false) {
                    $format.= '.u';
                }
                if ($content[strlen($content) - 1] == 'Z') {
                    $content = substr($content, 0, -1) . '+0000';
                }
                if (strpos($content, '-') !== false || strpos($content, '+') !== false) {
                    $format.= 'O';
                }
                $result = @DateTime::createFromFormat($format, $content);
                $result = $result ? $result->getTimestamp() : false;
                break;
            default:
                $result = $decoded['contents'];
                if (isset($mapping['mapping']) && isset($mapping['mapping'][$result])) {
                    $result = $mapping['mapping'][$result];
                }
                break;
        }
        return true;
    }

    protected static function values($decoded, &$result) {
        while ($decoded['class'] !== 0 &&
            isset($decoded['contents']) &&
            is_array($decoded['contents']) &&
            isset($decoded['contents']['tag'])
        ) {
            $decoded = $decoded['contents'];
        }
        switch ($decoded['tag']) {
            case static::TYPE_SEQUENCE:
            case static::TYPE_SET:
                foreach ($decoded['contents'] as $k => $v) {
                    $result[$k] = null;
                    static::values($v, $result[$k]);
                }
                break;
            case static::TYPE_OBJECT_IDENTIFIER:
                $result = array_search($decoded['contents'], static::$oids);
                if ($result === false) {
                    $result = $decoded['contents'];
                }
                break;
            default:
                $result = $decoded['contents'];
                break;
        }
        return true;
    }
}
