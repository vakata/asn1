<?php
/* Based on PHPSECLIB: https://github.com/phpseclib/phpseclib/blob/master/phpseclib/File/ASN1.php */

namespace vakata\asn1;

use DateTime;

/**
 * A class handling ASN1 encoding.
 */
class Encoder
{
    /**
     * Encode some data to DER using a mapping array.
     * @param  mixed     $source  the data to convert
     * @param  array     $mapping rules to convert by (check the example on https://github.com/vakata/asn1)
     * @return mixed             raw DER output (base64_encode if needed), false on failure
     */
    public static function encode($source, $mapping)
    {
        if (isset($mapping['default']) && $source === $mapping['default']) {
            return '';
        }

        $tag = $mapping['tag'];
        switch ($tag) {
            case ASN1::TYPE_SET:
            case ASN1::TYPE_SEQUENCE:
                $tag |= 0x20; // set the constructed bit
                $value = '';
                if (isset($mapping['min']) && isset($mapping['max'])) {
                    $child = $mapping['children'];
                    foreach ($source as $content) {
                        $temp = static::encode($content, $child);
                        if ($temp === false) {
                            return false;
                        }
                        $value .= $temp;
                    }
                    break;
                }
                if (isset($mapping['repeat'])) {
                    foreach ($source as $content) {
                        $temp = static::encode($content, $mapping['repeat']);
                        if ($temp === false) {
                            return false;
                        }
                        $value .= $temp;
                    }
                } else {
                    foreach ($mapping['children'] as $key => $child) {
                        if (!array_key_exists($key, $source)) {
                            if (!isset($child['optional'])) {
                                return false;
                            }
                            continue;
                        }
                        $temp = static::encode($source[$key], $child);
                        if ($temp === false) {
                            return false;
                        }
                        if ($temp === '') {
                            continue;
                        }
                        $value .= $temp;
                    }
                }
                break;
            case ASN1::TYPE_CHOICE:
                $temp = false;
                foreach ($mapping['children'] as $key => $child) {
                    if (!isset($source[$key])) {
                        continue;
                    }
                    $temp = static::encode($source[$key], $child);
                    if ($temp === false) {
                        return false;
                    }
                    if ($temp === '') {
                        continue;
                    }
                }
                return $temp;
            case ASN1::TYPE_INTEGER:
            case ASN1::TYPE_ENUMERATED:
                if (!isset($mapping['map']) && isset($mapping['base']) && $mapping['base'] === 16) {
                    if (strlen($source) % 2 == 1) {
                        $source = '0' . $source;
                    }
                    $value = hex2bin($source);
                } else {
                    if (!isset($mapping['map'])) {
                        $value = ASN1::toBase256($source, isset($mapping['base']) ? $mapping['base'] : 10);
                    } else {
                        $value = array_search($source, $mapping['map']);
                        if ($value === false) {
                            return false;
                        }
                        $value = ASN1::toBase256($value, isset($mapping['base']) ? (int)$mapping['base'] : 10);
                    }
                }
                if (!strlen($value)) {
                    $value = chr(0);
                }
                break;
            case ASN1::TYPE_UTC_TIME:
            case ASN1::TYPE_GENERALIZED_TIME:
                $format = $mapping['tag'] == ASN1::TYPE_UTC_TIME ? 'y' : 'Y';
                $format.= 'mdHis';
                $value = @gmdate($format, strtotime($source)) . 'Z';
                break;
            case ASN1::TYPE_BIT_STRING:
                if (isset($mapping['map'])) {
                    $mcnt = count($mapping['map']);
                    $bits = array_fill(0, $mcnt, 0);
                    $size = 0;
                    for ($i = 0; $i < $mcnt; $i++) {
                        if (in_array($mapping['map'][$i], $source)) {
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

                    for ($i = $size + 1; $i < $mcnt; $i++) {
                        unset($bits[$i]);
                    }

                    $bits = implode('', array_pad($bits, $size + $offset + 1, 0));
                    $bytes = explode(' ', rtrim(chunk_split($bits, 8, ' ')));
                    foreach ($bytes as $byte) {
                        $value.= chr((int)bindec($byte));
                    }

                    break;
                }
                // default to octet string if no mapping is present
            case ASN1::TYPE_OCTET_STRING:
                $value = isset($mapping['raw']) && $mapping['raw'] ? $source : base64_decode($source);
                break;
            case ASN1::TYPE_OBJECT_IDENTIFIER:
                if (!isset($source) && $mapping['optional']) {
                    return;
                }
                $oid = preg_match('(^(\d+\.?)+$)', $source) ? $source : ASN1::TextToOID($source);
                if (!preg_match('(^(\d+\.?)+$)', $oid)) {
                    throw new ASN1Exception('Invalid OID');
                }
                $parts = explode('.', $oid);
                $value = chr(40 * $parts[0] + $parts[1]);
                $pcnt = count($parts);
                for ($i = 2; $i < $pcnt; $i++) {
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
            case ASN1::TYPE_ANY:
                switch (true) {
                    case !isset($source):
                        return static::encode(null, array('tag' => ASN1::TYPE_NULL) + $mapping);
                    case is_int($source):
                        return static::encode($source, array('tag' => ASN1::TYPE_INTEGER) + $mapping);
                    case is_float($source):
                        return static::encode($source, array('tag' => ASN1::TYPE_REAL) + $mapping);
                    case is_bool($source):
                        return static::encode($source, array('tag' => ASN1::TYPE_BOOLEAN) + $mapping);
                    case is_string($source) && preg_match('(^(\d+\.?)+$)', $source):
                        return static::encode($source, array('tag' => ASN1::TYPE_OBJECT_IDENTIFIER) + $mapping);
                    default:
                        throw new ASN1Exception('Unrecognized type');
                }
                break;
            case ASN1::TYPE_NULL:
                $value = '';
                break;
            case ASN1::TYPE_NUMERIC_STRING:
            case ASN1::TYPE_TELETEX_STRING:
            case ASN1::TYPE_PRINTABLE_STRING:
            case ASN1::TYPE_UNIVERSAL_STRING:
            case ASN1::TYPE_UTF8_STRING:
            case ASN1::TYPE_BMP_STRING:
            case ASN1::TYPE_IA5_STRING:
            case ASN1::TYPE_VISIBLE_STRING:
            case ASN1::TYPE_VIDEOTEX_STRING:
            case ASN1::TYPE_GRAPHIC_STRING:
            case ASN1::TYPE_GENERAL_STRING:
                $value = $source;
                break;
            case ASN1::TYPE_BOOLEAN:
                $value = $source ? "\xFF" : "\x00";
                break;
            default:
                throw new ASN1Exception('Mapping provides no type definition');
        }

        $length = static::length(strlen($value));
        if (isset($mapping['name'])) {
            if (isset($mapping['implicit']) && $mapping['implicit']) {
                $tag = ((ASN1::CLASS_CONTEXT_SPECIFIC ?? 2) << 6) | (ord($value[0]) & 0x20) | $mapping['name'];
                return chr($tag) . $length . $value;
            } else {
                $value = chr($tag) . $length . $value;
                return chr(((ASN1::CLASS_CONTEXT_SPECIFIC ?? 2) << 6) | 0x20 | $mapping['name']) .
                    static::length(strlen($value)) .
                    $value;
            }
        }
        return chr($tag) . $length . $value;
    }

    protected static function length($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }
        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }
}
