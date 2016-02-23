# vakata\asn1\Timestamp
A class for timestamp request / response parsing

## Methods

| Name | Description |
|------|-------------|
|[generateRequestFromFile](#vakata\asn1\timestampgeneraterequestfromfile)|Generate a timestamp request (tsq) for a file path|
|[generateRequestFromData](#vakata\asn1\timestampgeneraterequestfromdata)|Generate a timestamp request (tsq) for a string|
|[parseRequestFromData](#vakata\asn1\timestampparserequestfromdata)|Parse a timestamp request|
|[parseRequestFromFile](#vakata\asn1\timestampparserequestfromfile)|Parse a timestamp request from a file|
|[parseResponseFromData](#vakata\asn1\timestampparseresponsefromdata)|Parse a timestamp response|
|[parseResponseFromFile](#vakata\asn1\timestampparseresponsefromfile)|Parse a timestamp response from a file|

---



### vakata\asn1\Timestamp::generateRequestFromFile
Generate a timestamp request (tsq) for a file path  


```php
public static function generateRequestFromFile (  
    string $path,  
    boolean|string $nonce,  
    boolean $requireCert,  
    string $alg,  
    string|null $policy  
) : string    
```

|  | Type | Description |
|-----|-----|-----|
| `$path` | `string` | the path to the file to be timestamped |
| `$nonce` | `boolean`, `string` | should a nonce be used - defaults to true, could be a value to use as nonce |
| `$requireCert` | `boolean` | should a certificate be returned in the response, defaults to false |
| `$alg` | `string` | the algorithm to use, defaults to 'sha1' |
| `$policy` | `string`, `null` | the policy to use, defaults to null |
|  |  |  |
| `return` | `string` | the raw timestamp request |

---


### vakata\asn1\Timestamp::generateRequestFromData
Generate a timestamp request (tsq) for a string  


```php
public static function generateRequestFromData (  
    string $data,  
    boolean|string $nonce,  
    boolean $requireCert,  
    string $alg,  
    string|null $policy  
) : string    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `string` | the data to be timestamped |
| `$nonce` | `boolean`, `string` | should a nonce be used - defaults to true, could be a value to use as nonce |
| `$requireCert` | `boolean` | should a certificate be returned in the response, defaults to false |
| `$alg` | `string` | the algorithm to use, defaults to 'sha1' |
| `$policy` | `string`, `null` | the policy to use, defaults to null |
|  |  |  |
| `return` | `string` | the raw timestamp request |

---


### vakata\asn1\Timestamp::parseRequestFromData
Parse a timestamp request  


```php
public static function parseRequestFromData (  
    string $data  
) : array    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `string` | the request |
|  |  |  |
| `return` | `array` | the parsed request |

---


### vakata\asn1\Timestamp::parseRequestFromFile
Parse a timestamp request from a file  


```php
public static function parseRequestFromFile (  
    string $path  
) : array    
```

|  | Type | Description |
|-----|-----|-----|
| `$path` | `string` | the path to the timestamp request file |
|  |  |  |
| `return` | `array` | the parsed request |

---


### vakata\asn1\Timestamp::parseResponseFromData
Parse a timestamp response  


```php
public static function parseResponseFromData (  
    string $data  
) : array    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `string` | the response |
|  |  |  |
| `return` | `array` | the parsed response |

---


### vakata\asn1\Timestamp::parseResponseFromFile
Parse a timestamp response from a file  


```php
public static function parseResponseFromFile (  
    string $data  
) : array    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `string` | the path to the timestamp response file |
|  |  |  |
| `return` | `array` | the parsed response |

---

