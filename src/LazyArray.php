<?php

namespace vakata\asn1;

class LazyArray implements \ArrayAccess, \Iterator, \Countable
{
    protected $data;
    protected $processor;

    public function __construct(array &$data = [], ?callable $processor = null)
    {
        $this->data = $data;
        $this->processor = $processor ?? function ($v) { return $v; };
    }
    public function __get($k)
    {
        return $this[$k] ?? null;
    }
    public function offsetExists($offset): bool
    {
        return isset($this->data[$offset]);
    }
    public function offsetGet($offset): mixed
    {
        return call_user_func($this->processor, $this->data[$offset]);
    }
    public function offsetSet($offset, $value) : void
    {
        throw new \Exception('Not supported');
    }
    public function offsetUnset($offset) : void
    {
        throw new \Exception('Not supported');
    }
    public function current(): mixed
    {
        return call_user_func($this->processor, current($this->data));
    }
    public function key(): mixed
    {
        return key($this->data);
    }
    public function next(): void
    {
        next($this->data);
    }
    public function rewind(): void
    {
        reset($this->data);
    }
    public function valid(): bool
    {
        return key($this->data) !== null;
    }
    public function count(): int
    {
        return count($this->data);
    }
    public function toArray(): array
    {
        return iterator_to_array($this);
    }
    public function rawData()
    {
        return $this->data;
    }
}
