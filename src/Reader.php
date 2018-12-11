<?php

namespace vakata\asn1;

class Reader
{
    protected $stream = null;

    public function __construct($stream)
    {
        $this->stream = $stream;
    }
    public static function fromString($data)
    {
        $stream = fopen('php://temp', 'r+');
        if ($stream) {
            fwrite($stream, $data);
            rewind($stream);
            return new static($stream);
        }
        throw new ASN1Exception('Could not create temp stream');
    }
    public static function fromFile($path)
    {
        return new static(fopen($path, 'r+'));
    }

    public function pos()
    {
        return ftell($this->stream);
    }
    public function byte()
    {
        return $this->bytes(1);
    }
    public function bytes($amount = null)
    {
        if ($amount === null) {
            $buff = '';
            while (!feof($this->stream)) {
                $buff .= fread($this->stream, 4096);
            }
            return $buff;
        }
        return fread($this->stream, $amount);
    }
    public function readUntil($val, $include = true)
    {
        $tmp = '';
        while (!feof($this->stream)) {
            $tmp .= $this->byte();
            if (substr($tmp, strlen($val) * -1) === $val) {
                break;
            }
        }
        return $include ? $tmp : substr($tmp, 0, strlen($val) * -1);
    }
    public function chunk($beg = 0, $length = null)
    {
        return $this->seek($beg)->bytes($length);
    }

    public function eof()
    {
        return feof($this->stream);
    }
    public function seek($pos)
    {
        fseek($this->stream, $pos);
        return $this;
    }
    public function rewind()
    {
        rewind($this->stream);
        return $this;
    }
}