# asn1

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Build Status][ico-travis]][link-travis]
[![Scrutinizer Code Quality][ico-code-quality]][link-scrutinizer]
[![Code Coverage][ico-scrutinizer]][link-scrutinizer]

Am ASN1 encoder / decoder.

## Install

Via Composer

``` bash
$ composer require vakata/asn1
```

## Usage

The main part of the library are the `Decoder` and `Encoder` classes.

```php
// first create an instance (there is a fromFile static method as well)
$decoded = \vakata\asn1\Decoder::fromString("...ASN1 data here ...");
// you can then inspect the parsed raw data
$decoded->structure(); // more info
$decoded->values(); // just values
// or map the data to an existing map
$decoded->map($mapArray);

// the encoder on the otherhand needs some data and a map
\vakata\asn1\Encoder::encode($dataArray, $mapArray);
```

There are helper classes in the `structures` namespace - these help with working with common known structures. All the structures have `fromString` and `fromFile` static constructor methods, and a `toArray` method.

``` php
// Timestamp example:
\vakata\asn1\structures\TimestampRequest::fromString($tsq)->toArray();
\vakata\asn1\structures\TimestampResponse::fromFile('/path/to/timestamp/response')->toArray();
\vakata\asn1\structures\TimestampRequest::generateFromFile('/path/to/file/to/timestamp');
// You can also work with Certificate, CRL, OCSPRequest, OCSPResponse, P7S
```

Read more in the [API docs](api.md)

## Testing

``` bash
$ composer test
```


## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email github@vakata.com instead of using the issue tracker.

## Credits

- [vakata][link-author]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information. 

[ico-version]: https://img.shields.io/packagist/v/vakata/asn1.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-travis]: https://img.shields.io/travis/vakata/asn1/master.svg?style=flat-square
[ico-scrutinizer]: https://img.shields.io/scrutinizer/coverage/g/vakata/asn1.svg?style=flat-square
[ico-code-quality]: https://img.shields.io/scrutinizer/g/vakata/asn1.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/vakata/asn1.svg?style=flat-square
[ico-cc]: https://img.shields.io/codeclimate/github/vakata/asn1.svg?style=flat-square
[ico-cc-coverage]: https://img.shields.io/codeclimate/coverage/github/vakata/asn1.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/vakata/asn1
[link-travis]: https://travis-ci.org/vakata/asn1
[link-scrutinizer]: https://scrutinizer-ci.com/g/vakata/asn1
[link-code-quality]: https://scrutinizer-ci.com/g/vakata/asn1
[link-downloads]: https://packagist.org/packages/vakata/asn1
[link-author]: https://github.com/vakata
[link-contributors]: ../../contributors
[link-cc]: https://codeclimate.com/github/vakata/asn1

