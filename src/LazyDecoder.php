<?php
/* Based on PHPSECLIB: https://github.com/phpseclib/phpseclib/blob/master/phpseclib/File/ASN1.php */

namespace vakata\asn1;

/**
 * A class handling ASN1 decoding.
 */
class LazyDecoder extends Decoder
{
    public function lazyDecodeHeader(array $header)
    {
        $this->reader->seek($header['content_start']);
        if ($header['class'] !== ASN1::CLASS_UNIVERSAL && $header['constructed']) {
            $header['children'] = $this->lazyParse(
                null,
                $header['length'] ? $header['start'] + $header['length'] - 1 : null,
                'header'
            );
        } elseif ($header['class'] === ASN1::CLASS_UNIVERSAL &&
            in_array($header['tag'], [ASN1::TYPE_SET, ASN1::TYPE_SEQUENCE])
        ) {
            $header['children'] = $this->lazyParse(
                null,
                $header['length'] ? $header['start'] + $header['length'] - 1 : null,
                'header'
            );
        } else {
            $header['value'] = $this->decode($header);
        }
        return $header;
    }
    public function lazyDecodeValue(array $header)
    {
        $this->reader->seek($header['content_start']);
        if ($header['class'] !== ASN1::CLASS_UNIVERSAL && $header['constructed']) {
            return $this->lazyParse(
                null,
                $header['length'] ? $header['start'] + $header['length'] - 1 : null,
                'value'
            );
        }
        if ($header['class'] === ASN1::CLASS_UNIVERSAL &&
            in_array($header['tag'], [ASN1::TYPE_SET, ASN1::TYPE_SEQUENCE])
        ) {
            return $this->lazyParse(
                null,
                $header['length'] ? $header['start'] + $header['length'] - 1 : null,
                'value'
            );
        }
        return $this->decode($header);
    }
    public function lazyParse($start = null, $max = null, string $mode = 'header')
    {
        if ($start !== null) {
            $this->reader->seek($start);
        }
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
            if ($header['length'] === null) {
                $this->reader->readUntil(chr(0).chr(0));
                $header['length'] = $this->reader->pos() - $header['start'];
                $header['content_length'] = $this->reader->pos() - $header['content_start'];
            } else {
                if ($header['content_length'] > 0) {
                    $this->reader->bytes($header['content_length']);
                }
            }
            $skeleton[] = $header;
        }
        switch ($mode) {
            case 'value':
                return new LazyArray($skeleton, function ($v) { return $this->lazyDecodeValue($v); });
            case 'header':
            default:
                return new LazyArray($skeleton, function ($v) { return $this->lazyDecodeHeader($v); });
        }
    }
    public function structure($max = null)
    {
        return $this->lazyParse(0, null, 'header');
    }
    public function values($skeleton = null)
    {
        return $this->lazyParse(0, null, 'value');
    }
    public function map($map, $skeleton = null)
    {
        $null = null;
        if ($skeleton === null && $this->reader->pos() !== 0) {
            $this->reader->rewind();
        }
        $skeleton = $skeleton ?? $this->structure()[0] ?? null;
        if (!isset($skeleton)) {
            throw new ASN1Exception('No decoded data for map');
        }
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
            return $null;
        } else {
            switch ($map['tag']) {
                case ASN1::TYPE_ANY_DER:
                    $temp = $this->reader->chunk($skeleton['start'], $skeleton['length']);
                    return $temp;
                case ASN1::TYPE_ANY_SKIP:
                    return $null;
                case ASN1::TYPE_ANY_RAW:
                    return $skeleton['value'] ?? null;
                case ASN1::TYPE_SET:
                    if (isset($map['repeat'])) {
                        $mapRepeat = $map['repeat'];
                        return new LazyArray($skeleton['children']->rawData(), function ($v) use ($mapRepeat) {
                            return $this->map($mapRepeat, $this->lazyDecodeHeader($v));
                        });
                    } else {
                        if (!isset($map['children'])) {
                            return $null;
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
                                            $vv['map'] = $v;
                                            $result[$k] = $vv;
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
                                        $vv['map'] = $v;
                                        $result[$k] = $vv;
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
                        return new LazyArray($result, function ($v) {
                            return $v === null ? null : $this->map($v['map'], $this->lazyDecodeHeader($v));
                        });
                    }
                    break;
                case ASN1::TYPE_SEQUENCE:
                    if (isset($map['repeat'])) {
                        $mapRepeat = $map['repeat'];
                        return new LazyArray($skeleton['children']->rawData(), function ($v) use ($mapRepeat) {
                            return $this->map($mapRepeat, $this->lazyDecodeHeader($v));
                        });
                    } else {
                        if (!isset($map['children'])) {
                            return $null;
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
                                    $vv['map'] = $v;
                                    $result[$k] = $vv;
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
                                        $vv['map'] = $v;
                                        $result[$k] = $vv;
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
                        return new LazyArray($result, function ($v) {
                            return $v === null ? null : $this->map($v['map'], $this->lazyDecodeHeader($v));
                        });
                    }
                    break;
                case ASN1::TYPE_OBJECT_IDENTIFIER:
                    $temp = isset($map['resolve']) && $map['resolve'] ?
                        ASN1::OIDtoText($skeleton['value']) :
                        $skeleton['value'];
                    return $temp;
                case ASN1::TYPE_OCTET_STRING:
                    if (isset($map['der']) && $map['der']) {
                        $temp = static::fromString($skeleton['value']);
                        $temp = isset($map['map']) ? $temp->map($map['map']) : $temp->values();
                        return $temp;
                    } else {
                        $temp = isset($map['raw']) && $map['raw'] ?
                            $skeleton['value'] :
                            base64_encode($skeleton['value']);
                        return $temp;
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
