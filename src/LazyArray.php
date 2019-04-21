<?php

namespace vakata\asn1;

class LazyArray implements \ArrayAccess, \Iterator, \Countable
{
    protected $data;
    protected $processor;

    public function __construct(array &$data = [], callable $processor = null)
    {
        $this->data = $data;
        $this->processor = $processor ?? function ($v) { return $v; };
    }
    public function __get($k)
    {
        return $this[$k] ?? null;
    }
    public function offsetExists($offset)
    {
        return isset($this->data[$offset]);
    }
    public function offsetGet($offset)
    {
        return call_user_func($this->processor, $this->data[$offset]);
    }
    public function offsetSet($offset, $value)
    {
        throw new \Exception('Not supported');
    }
    public function offsetUnset($offset)
    {
        throw new \Exception('Not supported');
    }
    public function current()
    {
        return call_user_func($this->processor, current($this->data));
    }
    public function key()
    {
        return key($this->data);
    }
    public function next()
    {
        return next($this->data);
    }
    public function rewind()
    {
        return reset($this->data);
    }
    public function valid()
    {
        return key($this->data) !== null;
    }
    public function count()
    {
        return count($this->data);
    }
    public function toArray()
    {
        return iterator_to_array($this);
    }
    public function rawData()
    {
        return $this->data;
    }
}