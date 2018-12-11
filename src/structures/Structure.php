<?php

namespace vakata\asn1\structures;

use \vakata\asn1\Decoder;

abstract class Structure
{
    protected $data;

    public function __construct($data)
    {
        $this->data = Decoder::fromString($data);
    }
    public static function fromString($data)
    {
        if (preg_match('(^[\-]+BEGIN.*?\n)i', $data)) {
            $data = base64_decode(preg_replace('(^[\-]+(BEGIN|END).*$)im', '', $data));
        }
        return new static($data);
    }
    public static function fromFile($path)
    {
        return static::fromString(file_get_contents($path));
    }

    public function structure()
    {
        return $this->data->structure();
    }
    public function toArray(bool $valuesOnly = false)
    {
        return $valuesOnly ? $this->data->values() : $this->data->map(static::map());
    }
    public function __toString()
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveArrayIterator($this->toArray()),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );
        $result = [];
        foreach ($iterator as $k => $v) {
            if (strlen($v)) {
                $result[] = str_repeat(' ', $iterator->getDepth()) . $v;
            }
        }
        return implode("\r\n", $result);
    }

    abstract protected static function map();
}
