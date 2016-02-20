<?php
/* Based on PHPSECLIB: https://github.com/phpseclib/phpseclib/blob/master/phpseclib/File/ASN1.php */

namespace vakata\asn1;

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
    const TYPE_CLASS_SEQUENCE    = 32;
    const TYPE_CHOICE            = -1;
    const TYPE_ANY               = -2;

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
        'authorityKeyIdentifier' =>'2.5.29.35',
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
        'tstinfo' =>              '1.2.840.113549.1.9.16.1.4', // RFC3161 TSTInfo
    ];

    /**
     * Convert a number to base256
     * @method toBase256
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
     * @method fromBase256
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
        return (int)base_convert($number, 2, $base);
    }

    /**
     * Encode some data to DER using a mapping array.
     * @method encodeDER
     * @param  mixed     $source  the data to convert
     * @param  array     $mapping rules to convert by (check the example on https://gihub.com/vakata/asn1)
     * @return string             raw DER output (base64_encode if needed)
     */
    public static function encodeDER($source, $mapping)
    {
        // do not encode (implicitly optional) fields with value set to default
        if (isset($mapping['default']) && $source === $mapping['default']) {
            return '';
        }

        $tag = $mapping['type'];

        switch ($tag) {
            case static::TYPE_SET:
            case static::TYPE_SEQUENCE:
                $tag|= 0x20; // set the constructed bit
                $value = '';

                // ignore the min and max
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

                    // An empty child encoding means it has been optimized out.
                    // Else we should have at least one tag byte.
                    if ($temp === '') {
                        continue;
                    }

                    // if isset($child['constant']) is true then isset($child['optional']) should be true as well
                    if (isset($child['constant'])) {
                        if (isset($child['explicit']) || $child['type'] == static::TYPE_CHOICE) {
                            $subtag = chr((static::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | $child['constant']);
                            $temp = $subtag . static::encodeLength(strlen($temp)) . $temp;
                        } else {
                            $subtag = chr(
                                (static::CLASS_CONTEXT_SPECIFIC << 6) | (ord($temp[0]) & 0x20) | $child['constant']
                            );
                            $temp = $subtag . substr($temp, 1);
                        }
                    }
                    $value.= $temp;
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

                    // An empty child encoding means it has been optimized out.
                    // Else we should have at least one tag byte.
                    if ($temp === '') {
                        continue;
                    }

                    $tag = ord($temp[0]);

                    // if isset($child['constant']) is true then isset($child['optional']) should be true as well
                    if (isset($child['constant'])) {
                        if (isset($child['explicit']) || $child['type'] == static::TYPE_CHOICE) {
                            $subtag = chr((static::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | $child['constant']);
                            $temp = $subtag . static::encodeLength(strlen($temp)) . $temp;
                        } else {
                            $subtag = chr((static::CLASS_CONTEXT_SPECIFIC << 6) | (ord($temp[0]) & 0x20) | $child['constant']);
                            $temp = $subtag . substr($temp, 1);
                        }
                    }
                }

                if ($temp && isset($mapping['cast'])) {
                    $temp[0] = chr(($mapping['class'] << 6) | ($tag & 0x20) | $mapping['cast']);
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
                $format = $mapping['type'] == static::TYPE_UTC_TIME ? 'y' : 'Y';
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
                /* The initial octet shall encode, as an unsigned binary integer with bit 1 as the least significant bit,
                   the number of unused bits in the final subsequent octet. The number shall be in the range zero to seven.

                   -- http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=16 */
                $value = base64_decode($source);
                break;
            case static::TYPE_OBJECT_IDENTIFIER:
                $oid = preg_match('#(?:\d+\.)+#', $source) ?
                  $source :
                  isset(static::$oids[$source]) ? static::$oids[$source] : false;
                if ($oid === false) {
                    throw new ASN1Exception('Invalid OID');
                    return false;
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
                        return static::encodeDER(null, array('type' => static::TYPE_NULL) + $mapping);
                    case is_int($source):
                        return static::encodeDER($source, array('type' => static::TYPE_INTEGER) + $mapping);
                    case is_float($source):
                        return static::encodeDER($source, array('type' => static::TYPE_REAL) + $mapping);
                    case is_bool($source):
                        return static::encodeDER($source, array('type' => static::TYPE_BOOLEAN) + $mapping);
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
                return false;
        }

        if (isset($mapping['cast'])) {
            if (isset($mapping['explicit']) || $mapping['type'] == static::TYPE_CHOICE) {
                $value = chr($tag) . static::encodeLength(strlen($value)) . $value;
                $tag = ($mapping['class'] << 6) | 0x20 | $mapping['cast'];
            } else {
                $tag = ($mapping['class'] << 6) | (ord($temp[0]) & 0x20) | $mapping['cast'];
            }
        }

        return chr($tag) . static::encodeLength(strlen($value)) . $value;
    }

    /**
     * Decode DER formatted data.
     * @method decodeDER
     * @param  string     $encoded raw DER input
     * @param  array|null $mapping optional mapping to follow (check the example on https://gihub.com/vakata/asn1)
     * @return array               the decoded object
     */
    public static function decodeDER($encoded, array $mapping = null)
    {
        $decoded = static::decode($encoded);
        if (!$mapping) {
            return $decoded;
        }
        $result = null;
        static::map($decoded, $mapping, $result);
        return $result;
    }

    protected static function map($decoded, $mapping, &$result)
    {
        if (in_array($mapping['type'], [ASN1::TYPE_SEQUENCE, ASN1::TYPE_SET]) &&
            in_array($decoded['type'], [ASN1::TYPE_SEQUENCE, ASN1::TYPE_SET])) {
            $mapping['type'] = $decoded['type'];
        }
        if ($mapping['type'] !== $decoded['type']) {
            if (!$mapping['optional']) {
                throw new ASN1Exception('Decoded data does not match mapping');
            }
            return false;
        }
        switch ($mapping['type']) {
            case static::TYPE_SET:
            case static::TYPE_SEQUENCE:
            case static::TYPE_CHOICE:
                $result = [];
                $i = 0;
                foreach ($mapping['children'] as $k => $v) {
                    $result[$k] = null;
                    if (static::map($decoded['content'][$i], $v, $result[$k])) {
                        $i++;
                    }
                }
                break;
            case static::TYPE_CLASS_SEQUENCE:
                $result = [];
                $i = 0;
                foreach ($mapping['children'] as $k => $v) {
                    $result[$k] = null;
                    if (static::map($decoded['content'][$i], $v, $result[$k])) {
                        $i++;
                    }
                }
                break;
            case static::TYPE_OBJECT_IDENTIFIER:
                $result = array_search($decoded['content'], static::$oids);
                if ($result === false) {
                    $result = $decoded['content'];
                }
                break;
            case static::TYPE_OCTET_STRING:
                $result = base64_encode($decoded['content']);
                break;
            default:
                $result = $decoded['content'];
                if (isset($mapping['mapping']) && isset($mapping['mapping'][$result])) {
                    $result = $mapping['mapping'][$result];
                }
                break;
        }
        return true;
    }

    protected static function decode($encoded, $start = 0)
    {
        $current = array('start' => $start);

        $type = ord(static::stringShift($encoded));
        $start++;

        $constructed = ($type >> 5) & 1;

        $tag = $type & 0x1F;
        if ($tag == 0x1F) {
            $tag = 0;
            // process septets (since the eighth bit is ignored, it's not an octet)
            do {
                $loop = ord($encoded[0]) >> 7;
                $tag <<= 7;
                $tag |= ord(static::stringShift($encoded)) & 0x7F;
                $start++;
            } while ($loop);
        }

        // Length, as discussed in paragraph 8.1.3 of X.690-0207.pdf#page=13
        $length = ord(static::stringShift($encoded));
        $start++;
        if ($length == 0x80) { // indefinite length
            // "[A sender shall] use the indefinite form (see 8.1.3.6) if the encoding is constructed and is not all
            //  immediately available." -- paragraph 8.1.3.2.c
            $length = strlen($encoded);
        } elseif ($length & 0x80) { // definite length, long form
            // technically, the long form of the length can be represented by up to 126 octets (bytes), but we'll only
            // support it up to four.
            $length&= 0x7F;
            $temp = static::stringShift($encoded, $length);
            // tags of indefinte length don't really have a header length; this length includes the tag
            $current+= array('headerlength' => $length + 2);
            $start+= $length;
            extract(unpack('Nlength', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4)));
        } else {
            $current+= array('headerlength' => 2);
        }

        if ($length > strlen($encoded)) {
            return false;
        }

        $content = static::stringShift($encoded, $length);

        // at this point $length can be overwritten. it's only accurate for definite length things as is

        /* Class is UNIVERSAL, APPLICATION, PRIVATE, or CONTEXT-SPECIFIC. The UNIVERSAL class is restricted to the ASN.1
           built-in types. It defines an application-independent data type that must be distinguishable from all other
           data types. The other three classes are user defined. The APPLICATION class distinguishes data types that
           have a wide, scattered use within a particular presentation context. PRIVATE distinguishes data types within
           a particular organization or country. CONTEXT-SPECIFIC distinguishes members of a sequence or set, the
           alternatives of a CHOICE, or universally tagged set members. Only the class number appears in braces for this
           data type; the term CONTEXT-SPECIFIC does not appear.

             -- http://www.obj-sys.com/asn1tutorial/node12.html */
        $class = ($type >> 6) & 3;
        switch ($class) {
            case self::CLASS_APPLICATION:
            case self::CLASS_PRIVATE:
            case self::CLASS_CONTEXT_SPECIFIC:
                if (!$constructed) {
                    return array(
                        'class'    => $class,
                        'type'     => ASN1::TYPE_CLASS_SEQUENCE,
                        'constant' => $tag,
                        'content'  => $content,
                        'length'   => $length + $start - $current['start']
                    );
                }

                $newcontent = array();
                $remainingLength = $length;
                while ($remainingLength > 0) {
                    $temp = static::decode($content, $start);
                    $length = $temp['length'];
                    // end-of-content octets - see paragraph 8.1.5
                    if (substr($content, $length, 2) == "\0\0") {
                        $length+= 2;
                        $start+= $length;
                        $newcontent[] = $temp;
                        break;
                    }
                    $start+= $length;
                    $remainingLength-= $length;
                    $newcontent[] = $temp;
                    static::stringShift($content, $length);
                }

                return array(
                    'class'    => $class,
                    'type'     => ASN1::TYPE_CLASS_SEQUENCE,
                    'constant' => $tag,
                    // the array encapsulation is for BC with the old format
                    'content'  => $newcontent,
                    // the only time when $content['headerlength'] isn't defined is when the length is indefinite.
                    // the absence of $content['headerlength'] is how we know if something is indefinite or not.
                    // technically, it could be defined to be 2 and then another indicator could be used but whatever.
                    'length'   => $start - $current['start']
                ) + $current;
        }

        $current+= array('type' => $tag);

        // decode UNIVERSAL tags
        switch ($tag) {
            case self::TYPE_BOOLEAN:
                // "The contents octets shall consist of a single octet." -- paragraph 8.2.1
                //if (strlen($content) != 1) {
                //    return false;
                //}
                $current['content'] = (bool) ord($content[0]);
                break;
            case self::TYPE_INTEGER:
            case self::TYPE_ENUMERATED:
                $current['content'] = static::fromBase256($content);
                break;
            case self::TYPE_REAL:
                // not currently supported
                return false;
            case self::TYPE_BIT_STRING:
                // The initial octet shall encode, as an unsigned binary integer with bit 1 as the least significant
                // bit, the number of unused bits in the final subsequent octet. The number shall be in the range zero
                // to seven.
                if (!$constructed) {
                    $current['content'] = $content;
                } else {
                    $temp = static::decode($content, $start);
                    $length-= strlen($content);
                    $last = count($temp) - 1;
                    for ($i = 0; $i < $last; $i++) {
                        // all subtags should be bit strings
                        //if ($temp[$i]['type'] != self::TYPE_BIT_STRING) {
                        //    return false;
                        //}
                        $current['content'].= substr($temp[$i]['content'], 1);
                    }
                    // all subtags should be bit strings
                    //if ($temp[$last]['type'] != self::TYPE_BIT_STRING) {
                    //    return false;
                    //}
                    $current['content'] = $temp[$last]['content'][0]
                                        . $current['content']
                                        . substr($temp[$i]['content'], 1);
                }
                break;
            case self::TYPE_OCTET_STRING:
                if (!$constructed) {
                    $current['content'] = $content;
                } else {
                    $current['content'] = '';
                    $length = 0;
                    while (substr($content, 0, 2) != "\0\0") {
                        $temp = static::decode($content, $length + $start);
                        static::stringShift($content, $temp['length']);
                        // all subtags should be octet strings
                        //if ($temp['type'] != self::TYPE_OCTET_STRING) {
                        //    return false;
                        //}
                        $current['content'].= $temp['content'];
                        $length+= $temp['length'];
                    }
                    if (substr($content, 0, 2) == "\0\0") {
                        $length+= 2; // +2 for the EOC
                    }
                }
                break;
            case self::TYPE_NULL:
                // "The contents octets shall not contain any octets." -- paragraph 8.8.2
                //if (strlen($content)) {
                //    return false;
                //}
                break;
            case self::TYPE_SEQUENCE:
            case self::TYPE_SET:
                $offset = 0;
                $current['content'] = array();
                while (strlen($content)) {
                    // if indefinite length construction was used and we have an end-of-content string next
                    // see paragraphs 8.1.1.3, 8.1.3.2, 8.1.3.6, 8.1.5, and (for an example) 8.6.4.2
                    if (!isset($current['headerlength']) && substr($content, 0, 2) == "\0\0") {
                        $length = $offset + 2; // +2 for the EOC
                        break 2;
                    }
                    $temp = static::decode($content, $start + $offset);
                    static::stringShift($content, $temp['length']);
                    $current['content'][] = $temp;
                    $offset+= $temp['length'];
                }
                break;
            case self::TYPE_OBJECT_IDENTIFIER:
                $temp = ord(static::stringShift($content));
                $current['content'] = sprintf('%d.%d', floor($temp / 40), $temp % 40);
                $valuen = 0;
                // process septets
                while (strlen($content)) {
                    $temp = ord(static::stringShift($content));
                    $valuen <<= 7;
                    $valuen |= $temp & 0x7F;
                    if (~$temp & 0x80) {
                        $current['content'].= ".$valuen";
                        $valuen = 0;
                    }
                }
                // the eighth bit of the last byte should not be 1
                //if ($temp >> 7) {
                //    return false;
                //}
                break;
            /* Each character string type shall be encoded as if it had been declared:
               [UNIVERSAL x] IMPLICIT OCTET STRING

                 -- X.690-0207.pdf#page=23 (paragraph 8.21.3)

               Per that, we're not going to do any validation.  If there are any illegal characters in the string,
               we don't really care */
            case self::TYPE_NUMERIC_STRING:
                // 0,1,2,3,4,5,6,7,8,9, and space
            case self::TYPE_PRINTABLE_STRING:
                // Upper and lower case letters, digits, space, apostrophe, left/right parenthesis, plus sign, comma,
                // hyphen, full stop, solidus, colon, equal sign, question mark
            case self::TYPE_TELETEX_STRING:
                // The Teletex character set in CCITT's T61, space, and delete
                // see http://en.wikipedia.org/wiki/Teletex#Character_sets
            case self::TYPE_VIDEOTEX_STRING:
                // The Videotex character set in CCITT's T.100 and T.101, space, and delete
            case self::TYPE_VISIBLE_STRING:
                // Printing character sets of international ASCII, and space
            case self::TYPE_IA5_STRING:
                // International Alphabet 5 (International ASCII)
            case self::TYPE_GRAPHIC_STRING:
                // All registered G sets, and space
            case self::TYPE_GENERAL_STRING:
                // All registered C and G sets, space and delete
            case self::TYPE_UTF8_STRING:
                // ????
            case self::TYPE_BMP_STRING:
                $current['content'] = $content;
                break;
            case self::TYPE_UTC_TIME:
            case self::TYPE_GENERALIZED_TIME:
                $current['content'] = $content;
            default:
        }

        $start+= $length;

        // ie. length is the length of the full TLV encoding - it's not just the length of the value
        return $current + array('length' => $start - $current['start']);
    }

    protected static function stringShift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }

    protected static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }
        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}
