# vakata\asn1\ASN1
A class handling ASN1 encoding / decoding.

## Methods

| Name | Description |
|------|-------------|
|[toBase256](#vakata\asn1\asn1tobase256)|Convert a number to base256|
|[fromBase256](#vakata\asn1\asn1frombase256)|Convert a number from base256|
|[encodeDER](#vakata\asn1\asn1encodeder)|Encode some data to DER using a mapping array.|
|[decodeDER](#vakata\asn1\asn1decodeder)|Decode DER formatted data.|

---



### vakata\asn1\ASN1::toBase256
Convert a number to base256  


```php
public static function toBase256 (  
    integer $number,  
    integer $base  
) : string    
```

|  | Type | Description |
|-----|-----|-----|
| `$number` | `integer` | the number to convert |
| `$base` | `integer` | the current base of the number (optional, defaults to 10) |
|  |  |  |
| `return` | `string` | the number in base256 |

---


### vakata\asn1\ASN1::fromBase256
Convert a number from base256  


```php
public static function fromBase256 (  
    string $string,  
    integer $base  
) : integer    
```

|  | Type | Description |
|-----|-----|-----|
| `$string` | `string` | the number to convert |
| `$base` | `integer` | the base to convert to (optional, defaults to 10) |
|  |  |  |
| `return` | `integer` | the converted number |

---


### vakata\asn1\ASN1::encodeDER
Encode some data to DER using a mapping array.  


```php
public static function encodeDER (  
    mixed $source,  
    array $mapping  
) : string    
```

|  | Type | Description |
|-----|-----|-----|
| `$source` | `mixed` | the data to convert |
| `$mapping` | `array` | rules to convert by (check the example on https://github.com/vakata/asn1) |
|  |  |  |
| `return` | `string` | raw DER output (base64_encode if needed) |

---


### vakata\asn1\ASN1::decodeDER
Decode DER formatted data.  


```php
public static function decodeDER (  
    string $encoded,  
    array|null $mapping  
) : array    
```

|  | Type | Description |
|-----|-----|-----|
| `$encoded` | `string` | raw DER input |
| `$mapping` | `array`, `null` | optional mapping to follow (check the example on https://github.com/vakata/asn1) |
|  |  |  |
| `return` | `array` | the decoded object |

---

