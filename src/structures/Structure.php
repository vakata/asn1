<?php

namespace vakata\asn1\structures;

use \vakata\asn1\Decoder;
use \vakata\asn1\LazyDecoder;
use \vakata\asn1\Reader;

abstract class Structure
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
     * Create an instance from a string.
     *
     * @param string $data
     * @return Structure
     */
    public static function fromString($data)
    {
        if (preg_match('(^[\-]+BEGIN.*?\n)i', $data)) {
            $data = base64_decode(preg_replace('(^[\-]+(BEGIN|END).*$)im', '', $data));
        }
        return new static(Reader::fromString($data));
    }
    /**
     * Create an instance from a file
     *
     * @param string $path the path to the file to parse
     * @return Structure
     */
    public static function fromFile($path)
    {
        $reader = Reader::fromFile($path);
        $data = $reader->bytes(1024);
        if (preg_match('(^[\-]+BEGIN.*?\n)i', $data)) {
            return static::fromString(
                base64_decode(preg_replace('(^[\-]+(BEGIN|END).*$)im', '', file_get_contents($path)))
            );
        }
        return new static(Reader::fromFile($path));
    }
    /**
     * Output the raw ASN1 structure of the data.
     *
     * @return array
     */
    public function structure(bool $lazy = false)
    {
        $this->reader->seek(0);
        $decoder = $lazy ? (new LazyDecoder($this->reader)) : (new Decoder($this->reader));
        return $decoder->structure();
    }
    /**
     * Get the mapped or values only view of the parsed data.
     *
     * @param boolean $valuesOnly should only values be returned or the map be used - defaults to `false` - use a map
     * @return mixed
     */
    public function toArray(bool $valuesOnly = false, bool $lazy = false)
    {
        $this->reader->seek(0);
        $decoder = $lazy ? (new LazyDecoder($this->reader)) : (new Decoder($this->reader));
        return $valuesOnly ? $decoder->values() : $decoder->map(static::map());
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
    public function getReader()
    {
        return $this->reader;
    }
    abstract protected static function map();
}
