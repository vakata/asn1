# vakata\asn1\Certificate
A class for x509 certificate parsing

## Methods

| Name | Description |
|------|-------------|
|[parseData](#vakata\asn1\certificateparsedata)|Parse a certificate|
|[parseFile](#vakata\asn1\certificateparsefile)|Parse a certificate from a file|

---



### vakata\asn1\Certificate::parseData
Parse a certificate  


```php
public static function parseData (  
    string $data  
) : array    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `string` | the certificate |
|  |  |  |
| `return` | `array` | the parsed certificate |

---


### vakata\asn1\Certificate::parseFile
Parse a certificate from a file  


```php
public static function parseFile (  
    string $path  
) : array    
```

|  | Type | Description |
|-----|-----|-----|
| `$path` | `string` | the path to the certificate file |
|  |  |  |
| `return` | `array` | the parsed certificate |

---

