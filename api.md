## Table of contents

- [\vakata\asn1\ASN1](#class-vakataasn1asn1)
- [\vakata\asn1\ASN1Exception](#class-vakataasn1asn1exception)
- [\vakata\asn1\Decoder](#class-vakataasn1decoder)
- [\vakata\asn1\Encoder](#class-vakataasn1encoder)
- [\vakata\asn1\Reader](#class-vakataasn1reader)
- [\vakata\asn1\structures\Certificate](#class-vakataasn1structurescertificate)
- [\vakata\asn1\structures\Common](#class-vakataasn1structurescommon)
- [\vakata\asn1\structures\CRL](#class-vakataasn1structurescrl)
- [\vakata\asn1\structures\OCSPRequest](#class-vakataasn1structuresocsprequest)
- [\vakata\asn1\structures\OCSPResponse](#class-vakataasn1structuresocspresponse)
- [\vakata\asn1\structures\P7S](#class-vakataasn1structuresp7s)
- [\vakata\asn1\structures\Structure (abstract)](#class-vakataasn1structuresstructure-abstract)
- [\vakata\asn1\structures\TimestampRequest](#class-vakataasn1structurestimestamprequest)
- [\vakata\asn1\structures\TimestampResponse](#class-vakataasn1structurestimestampresponse)

<hr />

### Class: \vakata\asn1\ASN1

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>OIDtoText(</strong><em>mixed</em> <strong>$id</strong>)</strong> : <em>void</em> |
| public static | <strong>TextToOID(</strong><em>mixed</em> <strong>$text</strong>)</strong> : <em>void</em> |
| public static | <strong>fromBase256(</strong><em>string</em> <strong>$string</strong>)</strong> : <em>integer/string the converted number</em><br /><em>Convert a number from base256</em> |
| public static | <strong>toBase256(</strong><em>integer</em> <strong>$number</strong>, <em>integer</em> <strong>$base=10</strong>)</strong> : <em>string the number in base256</em><br /><em>Convert a number to base256</em> |

<hr />

### Class: \vakata\asn1\ASN1Exception

| Visibility | Function |
|:-----------|:---------|

*This class extends \Exception*

*This class implements \Throwable*

<hr />

### Class: \vakata\asn1\Decoder

> A class handling ASN1 decoding.

| Visibility | Function |
|:-----------|:---------|
| public | <strong>__construct(</strong><em>[\vakata\asn1\Reader](#class-vakataasn1reader)</em> <strong>$reader</strong>)</strong> : <em>void</em><br /><em>Create an instance by passing in an instantiated reader.</em> |
| public static | <strong>fromFile(</strong><em>string</em> <strong>$path</strong>)</strong> : <em>[\vakata\asn1\Decoder](#class-vakataasn1decoder)</em><br /><em>Create a new instance from a file.</em> |
| public static | <strong>fromString(</strong><em>string</em> <strong>$data</strong>)</strong> : <em>[\vakata\asn1\Decoder](#class-vakataasn1decoder)</em><br /><em>Create a new instance from an ASN1 string.</em> |
| public | <strong>map(</strong><em>array</em> <strong>$map</strong>, <em>mixed</em> <strong>$skeleton=null</strong>)</strong> : <em>mixed in most cases this is an array, as all complex structures are either a sequence or a set</em><br /><em>Map the parsed data to a map</em> |
| public | <strong>structure(</strong><em>mixed</em> <strong>$max=null</strong>)</strong> : <em>mixed in most cases this is an array, as all complex structures are either a sequence or a set</em><br /><em>Dump the parsed structure of the ASN1 data.</em> |
| public | <strong>values(</strong><em>mixed</em> <strong>$skeleton=null</strong>)</strong> : <em>mixed in most cases this is an array, as all complex structures are either a sequence or a set</em><br /><em>Dump the parsed values only.</em> |
| protected | <strong>decode(</strong><em>mixed</em> <strong>$header</strong>)</strong> : <em>void</em> |
| protected | <strong>header()</strong> : <em>void</em> |

<hr />

### Class: \vakata\asn1\Encoder

> A class handling ASN1 encoding.

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>encode(</strong><em>mixed</em> <strong>$source</strong>, <em>array</em> <strong>$mapping</strong>)</strong> : <em>mixed raw DER output (base64_encode if needed), false on failure</em><br /><em>Encode some data to DER using a mapping array.</em> |
| protected static | <strong>length(</strong><em>mixed</em> <strong>$length</strong>)</strong> : <em>void</em> |

<hr />

### Class: \vakata\asn1\Reader

| Visibility | Function |
|:-----------|:---------|
| public | <strong>__construct(</strong><em>mixed</em> <strong>$stream</strong>)</strong> : <em>void</em> |
| public | <strong>byte()</strong> : <em>void</em> |
| public | <strong>bytes(</strong><em>mixed</em> <strong>$amount=null</strong>)</strong> : <em>void</em> |
| public | <strong>chunk(</strong><em>mixed</em> <strong>$beg</strong>, <em>mixed</em> <strong>$length=null</strong>)</strong> : <em>void</em> |
| public | <strong>eof()</strong> : <em>void</em> |
| public static | <strong>fromFile(</strong><em>mixed</em> <strong>$path</strong>)</strong> : <em>void</em> |
| public static | <strong>fromString(</strong><em>mixed</em> <strong>$data</strong>)</strong> : <em>void</em> |
| public | <strong>pos()</strong> : <em>void</em> |
| public | <strong>readUntil(</strong><em>mixed</em> <strong>$val</strong>, <em>bool</em> <strong>$include=true</strong>)</strong> : <em>void</em> |
| public | <strong>rewind()</strong> : <em>void</em> |
| public | <strong>seek(</strong><em>mixed</em> <strong>$pos</strong>)</strong> : <em>void</em> |

<hr />

### Class: \vakata\asn1\structures\Certificate

> A class for x509 certificate parsing

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>map()</strong> : <em>void</em> |

*This class extends [\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)*

<hr />

### Class: \vakata\asn1\structures\Common

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>AlgorithmIdentifier()</strong> : <em>void</em> |
| public static | <strong>RDNSequence()</strong> : <em>void</em> |
| public static | <strong>extensions()</strong> : <em>void</em> |

<hr />

### Class: \vakata\asn1\structures\CRL

> A class for CRL parsing

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>map()</strong> : <em>void</em> |

*This class extends [\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)*

<hr />

### Class: \vakata\asn1\structures\OCSPRequest

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>generate(</strong><em>\string</em> <strong>$algorithm</strong>, <em>\string</em> <strong>$issuerNameHash</strong>, <em>\string</em> <strong>$issuerKeyHash</strong>, <em>\string</em> <strong>$serialNumber</strong>, <em>\string</em> <strong>$requestor=null</strong>)</strong> : <em>void</em> |
| public static | <strong>map()</strong> : <em>void</em> |

*This class extends [\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)*

<hr />

### Class: \vakata\asn1\structures\OCSPResponse

> A class for OCSP parsing

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>map()</strong> : <em>void</em> |
| public | <strong>subject()</strong> : <em>void</em> |

*This class extends [\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)*

<hr />

### Class: \vakata\asn1\structures\P7S

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>map()</strong> : <em>void</em> |

*This class extends [\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)*

<hr />

### Class: \vakata\asn1\structures\Structure (abstract)

| Visibility | Function |
|:-----------|:---------|
| public | <strong>__construct(</strong><em>string</em> <strong>$data</strong>)</strong> : <em>void</em><br /><em>Create an instance.</em> |
| public | <strong>__toString()</strong> : <em>void</em> |
| public static | <strong>fromFile(</strong><em>string</em> <strong>$path</strong>)</strong> : <em>[\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)</em><br /><em>Create an instance from a file</em> |
| public static | <strong>fromString(</strong><em>string</em> <strong>$data</strong>)</strong> : <em>[\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)</em><br /><em>Create an instance from a string.</em> |
| public | <strong>structure()</strong> : <em>array</em><br /><em>Output the raw ASN1 structure of the data.</em> |
| public | <strong>toArray(</strong><em>\boolean</em> <strong>$valuesOnly=false</strong>)</strong> : <em>mixed</em><br /><em>Get the mapped or values only view of the parsed data.</em> |
| protected static | <strong>abstract map()</strong> : <em>void</em> |

<hr />

### Class: \vakata\asn1\structures\TimestampRequest

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>generateFromData(</strong><em>string</em> <strong>$data</strong>, <em>bool/boolean/string</em> <strong>$nonce=true</strong>, <em>bool/boolean</em> <strong>$requireCert=false</strong>, <em>string</em> <strong>$alg=`'sha1'`</strong>, <em>string/null</em> <strong>$policy=null</strong>)</strong> : <em>string the raw timestamp request</em><br /><em>Generate a timestamp request (tsq) for a string</em> |
| public static | <strong>generateFromFile(</strong><em>string</em> <strong>$path</strong>, <em>bool/boolean/string</em> <strong>$nonce=true</strong>, <em>bool/boolean</em> <strong>$requireCert=false</strong>, <em>string</em> <strong>$alg=`'sha1'`</strong>, <em>string/null</em> <strong>$policy=null</strong>)</strong> : <em>string the raw timestamp request</em><br /><em>Generate a timestamp request (tsq) for a file path</em> |
| public static | <strong>generateFromHash(</strong><em>string</em> <strong>$data</strong>, <em>bool/boolean/string</em> <strong>$nonce=true</strong>, <em>bool/boolean</em> <strong>$requireCert=false</strong>, <em>string</em> <strong>$alg=`'sha1'`</strong>, <em>string/null</em> <strong>$policy=null</strong>)</strong> : <em>string the raw timestamp request</em><br /><em>Generate a timestamp request (tsq) for a given hash</em> |
| public static | <strong>map()</strong> : <em>void</em> |

*This class extends [\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)*

<hr />

### Class: \vakata\asn1\structures\TimestampResponse

| Visibility | Function |
|:-----------|:---------|
| public static | <strong>map()</strong> : <em>void</em> |
| public static | <strong>mapToken()</strong> : <em>void</em> |

*This class extends [\vakata\asn1\structures\Structure](#class-vakataasn1structuresstructure-abstract)*

