<?php
/* Based on PHPSECLIB: https://github.com/phpseclib/phpseclib/blob/master/phpseclib/File/ASN1.php */

namespace vakata\asn1;

use DateTime;

/**
 * A class handling ASN1 decoding.
 */
class Decoder
{
    protected $reader;

    /**
     * Create an instance by passing in an instantiated reader.
     *
     * @param Reader $reader
     */
    public function __construct(Reader $reader)
    {
        $this->reader = $reader;
    }
    /**
     * Create a new instance from an ASN1 string.
     *
     * @param string $data the ASN1 data
     * @return Decoder
     */
    public static function fromString($data)
    {
        return new static(Reader::fromString($data));
    }
    /**
     * Create a new instance from a file.
     *
     * @param string $path the path to the file to parse
     * @return Decoder
     */
    public static function fromFile($path)
    {
        return new static(Reader::fromFile($path));
    }

    protected function header()
    {
        $start = $this->reader->pos();
        $identifier = ord($this->reader->byte());
        $constructed = ($identifier >> 5) & 1; // 6th bit
        $class = ($identifier >> 6) & 3; // 7th and 8th bits
        $tag = $identifier & 31; // first 5 bits
        if ($tag === 31) { // long tag (read each 7 bits until the 8th is 0)
            $tag = 0;
            while (true) {
                $temp = ord($this->reader->byte());
                $tag <<= 7;
                $tag |= $temp & 127;
                if (($temp & 128) === 0) {
                    break;
                }
            }
        }
        if ($tag === 0 && $class === 0) {
            return [
                'constructed' => $constructed,
                'class' => $class,
                'tag' => $tag,
                'start' => $start,
                'length' => ($this->reader->pos() - $start),
                'content_start' => $this->reader->pos(),
                'content_length' => 0
            ];
        }
        $temp = ord($this->reader->byte());
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
                $length |= ord($this->reader->byte());
            }
        } else {
            // short form
            $length = $temp;
        }
        return [
            'constructed' => $constructed,
            'class' => $class,
            'tag' => $tag,
            'start' => $start,
            'length' => $length !== null ? $length + ($this->reader->pos() - $start) : null,
            'content_start' => $this->reader->pos(),
            'content_length' => $length
        ];
    }
    protected function decode($header)
    {
        $contents = $header['content_length'] > 0 ?
            $this->reader->chunk($header['content_start'], $header['content_length']) :
            '';
        if ($header['class'] !== ASN1::CLASS_UNIVERSAL) {
            return $contents;
        }
        switch ($header['tag']) {
            case ASN1::TYPE_BOOLEAN:
                return (bool)ord($contents[0]);
            case ASN1::TYPE_INTEGER:
                return ASN1::fromBase256($contents);
            case ASN1::TYPE_ENUMERATED:
                return (int)base_convert(ASN1::fromBase256($contents), 2, 10);
            case ASN1::TYPE_REAL:
                // TODO: read the specs
                return false;
            case ASN1::TYPE_BIT_STRING:
                if ($header['constructed']) {
                    $temp = static::fromString($contents)->values();
                    $real = '';
                    for ($i = 0; $i < count($temp) - 1; $i++) {
                        $real .= $temp['value'];
                    }
                    return $temp[count($temp) - 1]['value'][0] . $real . substr($temp[$i]['value'], 1);
                }
                return $contents;
            case ASN1::TYPE_OCTET_STRING:
                if ($header['constructed']) {
                    return implode('', array_map(function ($v) {
                        return $v['value'];
                    }, static::fromString($contents)->values()));
                }
                return $contents;
            case ASN1::TYPE_NULL:
                return null;
            case ASN1::TYPE_UTC_TIME:
                $format = 'YmdHis';
                $matches = [];
                if (preg_match('#^(\d{10})(Z|[+-]\d{4})$#', $contents, $matches)) {
                    $contents = $matches[1] . '00' . $matches[2];
                }
                $prefix = substr($contents, 0, 2) >= 50 ? '19' : '20';
                $contents = $prefix . $contents;
                if ($contents[strlen($contents) - 1] == 'Z') {
                    $contents = substr($contents, 0, -1) . '+0000';
                }
                if (strpos($contents, '-') !== false || strpos($contents, '+') !== false) {
                    $format .= 'O';
                }
                $result = @DateTime::createFromFormat($format, $contents);
                return $result ? $result->getTimestamp() : false;
            case ASN1::TYPE_GENERALIZED_TIME:
                $format = 'YmdHis';
                if (strpos($contents, '.') !== false) {
                    $format .= '.u';
                }
                if ($contents[strlen($contents) - 1] == 'Z') {
                    $contents = substr($contents, 0, -1) . '+0000';
                }
                if (strpos($contents, '-') !== false || strpos($contents, '+') !== false) {
                    $format .= 'O';
                }
                $result = @DateTime::createFromFormat($format, $contents);
                return $result ? $result->getTimestamp() : false;
            case ASN1::TYPE_OBJECT_IDENTIFIER:
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
                return $real;
            default:
                return $contents;
        }
    }
    /**
     * Dump the parsed structure of the ASN1 data.
     *
     * @param mixed $max internal - do not use
     * @return mixed in most cases this is an array, as all complex structures are either a sequence or a set
     */
    public function structure($max = null)
    {
        $skeleton = [];
        while (!$this->reader->eof() && ($max === null || $this->reader->pos() < $max)) {
            $header = $this->header();
            if ($header['class'] === 0 && $header['tag'] === 0) {
                if ($max === null) {
                    break;
                } else {
                    continue;
                }
            }
            if ($header['class'] !== ASN1::CLASS_UNIVERSAL && $header['constructed']) {
                $header['children'] = $this->structure(
                    $header['length'] ? $header['start'] + $header['length'] - 1 : null
                );
                if ($header['length'] === null) {
                    $this->reader->byte();
                    $header['length'] = $this->reader->pos() - $header['start'];
                    $header['content_length'] = $this->reader->pos() - $header['content_start'];
                }
                $skeleton[] = $header;
            } else {
                if ($header['class'] === ASN1::CLASS_UNIVERSAL &&
                    in_array($header['tag'], [ASN1::TYPE_SET, ASN1::TYPE_SEQUENCE])
                ) {
                    $header['children'] = $this->structure(
                        $header['length'] ? $header['start'] + $header['length'] - 1 : null
                    );
                    if ($header['length'] === null) {
                        $this->reader->byte();
                        $header['length'] = $this->reader->pos() - $header['start'];
                        $header['content_length'] = $this->reader->pos() - $header['content_start'];
                    }
                } else {
                    if ($header['length'] === null) {
                        $this->reader->readUntil(chr(0).chr(0));
                        $header['length'] = $this->reader->pos() - $header['start'];
                        $header['content_length'] = $this->reader->pos() - $header['content_start'];
                    } else {
                        if ($header['content_length'] > 0) {
                            $this->reader->bytes($header['content_length']);
                        }
                    }
                }
                if (!isset($header['children'])) {
                    $pos = $this->reader->pos();
                    $header['value'] = $this->decode($header);
                    $this->reader->seek($pos);
                }
                $skeleton[] = $header;
            }
        }
        return $skeleton;
    }
    /**
     * Dump the parsed values only.
     *
     * @param mixed $skeleton internal - do not use
     * @return mixed in most cases this is an array, as all complex structures are either a sequence or a set
     */
    public function values($skeleton = null)
    {
        $skeleton = $skeleton ?? $this->structure();
        foreach ($skeleton as $k => $v) {
            if (isset($v['children'])) {
                $skeleton[$k] = $this->values($v['children']);
            } else {
                $skeleton[$k] = $v['value'] ?? null;
            }
        }
        return $skeleton;
    }
    /**
     * Map the parsed data to a map
     *
     * @param array $map the map to use - look in the structure classes for example map arrays
     * @param mixed $skeleton internal - do not use
     * @return mixed in most cases this is an array, as all complex structures are either a sequence or a set
     */
    public function map($map, $skeleton = null)
    {
        if ($skeleton === null && $this->reader->pos() !== 0) {
            $this->reader->rewind();
        }
        $skeleton = $skeleton ?? $this->structure()[0];
        if ($skeleton['class'] !== ASN1::CLASS_UNIVERSAL) {
            if ($map['tag'] === ASN1::TYPE_CHOICE) {
                foreach ($map['children'] as $child) {
                    if (isset($child['name']) && (int)$skeleton['tag'] === (int)$child['name']) {
                        $map = $child;
                        if (isset($child['value']) && $child['value']) {
                            return $child['value'];
                        }
                        break;
                    }
                }
            }
        }
        if ($skeleton['class'] !== ASN1::CLASS_UNIVERSAL) {
            if (isset($map['implicit']) && $map['implicit']) {
                $skeleton['class'] = ASN1::CLASS_UNIVERSAL;
                $skeleton['tag'] = $map['tag'];
            } else {
                $skeleton = $skeleton['children'][0] ?? null;
            }
        }
        if ($map['tag'] === ASN1::TYPE_CHOICE) {
            foreach ($map['children'] as $child) {
                if ($skeleton['tag'] === $child['tag']) {
                    $map = $child;
                    if (isset($child['value']) && $child['value']) {
                        return $child['value'];
                    }
                    break;
                }
            }
        }
        if (in_array($map['tag'], [ASN1::TYPE_SEQUENCE, ASN1::TYPE_SET]) &&
            in_array($skeleton['tag'], [ASN1::TYPE_SEQUENCE, ASN1::TYPE_SET])) {
            $map['tag'] = $skeleton['tag'];
        }
        if ($map['tag'] === ASN1::TYPE_ANY && isset($skeleton['tag'])) {
            $map['tag'] = $skeleton['tag'];
        }
        if (!in_array($map['tag'], [ASN1::TYPE_ANY, ASN1::TYPE_ANY_RAW, ASN1::TYPE_ANY_SKIP, ASN1::TYPE_ANY_DER]) &&
            $map['tag'] !== $skeleton['tag']
        ) {
            if (!isset($map['optional']) || !$map['optional']) {
                throw new ASN1Exception('Decoded data does not match mapping - ' . $skeleton['tag']);
            }
            return null;
        } else {
            switch ($map['tag']) {
                case ASN1::TYPE_ANY_DER:
                    return $this->reader->chunk($skeleton['start'], $skeleton['length']);
                case ASN1::TYPE_ANY_SKIP:
                    return null;
                case ASN1::TYPE_ANY_RAW:
                    return $skeleton['value'] ?? null;
                case ASN1::TYPE_SET:
                    if (isset($map['repeat'])) {
                        $result = [];
                        foreach ($skeleton['children'] as $v) {
                            $result[] = $this->map($map['repeat'], $v);
                        }
                        return $result;
                    } else {
                        if (!isset($map['children'])) {
                            return null;
                        }
                        $temp = $skeleton['children'];
                        $result = [];
                        // named first
                        foreach ($map['children'] as $k => $v) {
                            if (isset($v['name'])) {
                                $result[$k] = null;
                                foreach ($temp as $kk => $vv) {
                                    if ($vv['class'] !== ASN1::CLASS_UNIVERSAL && (int)$v['name'] === $vv['tag']) {
                                        try {
                                            if (isset($v['implicit']) && $v['implicit']) {
                                                $vv['class'] = ASN1::CLASS_UNIVERSAL;
                                                $vv['tag'] = $map['tag'];
                                            } else {
                                                $vv = $vv['children'][0] ?? null;
                                            }
                                            $result[$k] = $this->map($v, $vv);
                                            unset($temp[$kk]);
                                            break;
                                        } catch (ASN1Exception $e) {
                                            // continue trying other children in case of failure
                                        }
                                    }
                                }
                                if ($result[$k] === null && (!isset($v['optional']) || !$v['optional'])) {
                                    throw new ASN1Exception('Missing tagged type - ' . $k);
                                }
                            }
                        }
                        foreach ($map['children'] as $k => $v) {
                            if (isset($v['name'])) {
                                continue;
                            }
                            $result[$k] = null;
                            foreach ($temp as $kk => $vv) {
                                if ($v['tag'] === $vv['tag'] ||
                                    in_array(
                                        $v['tag'],
                                        [
                                            ASN1::TYPE_ANY,
                                            ASN1::TYPE_ANY_DER,
                                            ASN1::TYPE_ANY_RAW,
                                            ASN1::TYPE_ANY_SKIP,
                                            ASN1::TYPE_CHOICE
                                        ]
                                    )
                                ) {
                                    try {
                                        $result[$k] = $this->map($v, $vv);
                                        unset($temp[$kk]);
                                        break;
                                    } catch (ASN1Exception $e) {
                                        $result[$k] = null;
                                    }
                                }
                            }
                            if ($result[$k] === null && (!isset($v['optional']) || !$v['optional'])) {
                                throw new ASN1Exception('Decoded data does not match mapping - ' . $k);
                            }
                        }
                        return $result;
                    }
                    break;
                case ASN1::TYPE_SEQUENCE:
                    if (isset($map['repeat'])) {
                        $result = [];
                        foreach ($skeleton['children'] as $v) {
                            $result[] = $this->map($map['repeat'], $v);
                        }
                        return $result;
                    } else {
                        if (!isset($map['children'])) {
                            return null;
                        }
                        $result = [];
                        foreach ($skeleton['children'] as $vv) {
                            foreach ($map['children'] as $k => $v) {
                                if (isset($v['name']) && $vv['class'] !== ASN1::CLASS_UNIVERSAL &&
                                    (int)$v['name'] === $vv['tag']
                                ) {
                                    if (isset($v['implicit']) && $v['implicit']) {
                                        $vv['class'] = ASN1::CLASS_UNIVERSAL;
                                        $vv['tag'] = $map['tag'];
                                    } else {
                                        $vv = $vv['children'][0] ?? null;
                                    }
                                    $result[$k] = $this->map($v, $vv);
                                    unset($map['children'][$k]);
                                    break;
                                }
                                if (!isset($v['name']) &&
                                    (
                                        $v['tag'] === $vv['tag'] ||
                                        in_array(
                                            $v['tag'],
                                            [
                                                ASN1::TYPE_ANY,
                                                ASN1::TYPE_ANY_DER,
                                                ASN1::TYPE_ANY_RAW,
                                                ASN1::TYPE_ANY_SKIP,
                                                ASN1::TYPE_CHOICE
                                            ]
                                        )
                                    )
                                ) {
                                    try {
                                        $temp = $this->map($v, $vv);
                                        $result[$k] = $temp;
                                        unset($map['children'][$k]);
                                        break;
                                    } catch (ASN1Exception $e) {
                                        // continue trying other children in case of failure
                                    }
                                }
                                if (!isset($v['optional']) || !$v['optional']) {
                                    throw new ASN1Exception('Missing type - ' . $k);
                                } else {
                                    $result[$k] = null;
                                    unset($map['children'][$k]);
                                }
                            }
                        }
                        return $result;
                    }
                    break;
                case ASN1::TYPE_OBJECT_IDENTIFIER:
                    return isset($map['resolve']) && $map['resolve'] ?
                        ASN1::OIDtoText($skeleton['value']) :
                        $skeleton['value'];
                case ASN1::TYPE_OCTET_STRING:
                    if (isset($map['der']) && $map['der']) {
                        $temp = static::fromString($skeleton['value']);
                        return isset($map['map']) ? $temp->map($map['map']) : $temp->values();
                    } else {
                        return isset($map['raw']) && $map['raw'] ?
                            $skeleton['value'] :
                            base64_encode($skeleton['value']);
                    }
                    break;
                case ASN1::TYPE_INTEGER:
                    $base = isset($map['base']) && (int)$map['base'] ? (int)$map['base'] : 10;
                    if ($base < 3) {
                        $result = $skeleton['value'];
                    } else {
                        if (strlen($skeleton['value']) > 53 && $base === 16) {
                            $hex = '';
                            for ($i = strlen($skeleton['value']) - 4; $i >= 0; $i-=4) {
                                $hex .= dechex((int)bindec(substr($skeleton['value'], $i, 4)));
                            }
                            $result = strrev($hex);
                        } else {
                            $temp = base_convert($skeleton['value'], 2, $base);
                            if ($base === 10) {
                                $temp = (int)$temp;
                            }
                            $result = $temp;
                        }
                    }
                    if (isset($map['map']) && isset($map['map'][$result])) {
                        $result = $map['map'][$result];
                    }
                    return $result;
                case ASN1::TYPE_UTC_TIME:
                case ASN1::TYPE_GENERALIZED_TIME:
                    return $skeleton['value'];
                default:
                    $result = $skeleton['value'];
                    if (isset($map['map']) && isset($map['map'][$result])) {
                        $result = $map['map'][$result];
                    }
                    return $result;
            }
        }
    }
}
