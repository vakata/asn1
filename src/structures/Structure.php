<?php

namespace vakata\asn1\structures;

use \vakata\asn1\Decoder;

abstract class Structure
{
    protected $data;

    /**
     * Create an instance.
     *
     * @param string $data
     */
    public function __construct($data)
    {
        $this->data = Decoder::fromString($data);
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
        return new static($data);
    }
    /**
     * Create an instance from a file
     *
     * @param string $path the path to the file to parse
     * @return Structure
     */
    public static function fromFile($path)
    {
        return static::fromString(file_get_contents($path));
    }
    /**
     * Output the raw ASN1 structure of the data.
     *
     * @return array
     */
    public function structure()
    {
        return $this->data->structure();
    }
    /**
     * Get the mapped or values only view of the parsed data.
     *
     * @param boolean $valuesOnly should only values be returned or the map be used - defaults to `false` - use a map
     * @return mixed
     */
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
