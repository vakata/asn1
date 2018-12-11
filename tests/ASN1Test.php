<?php
namespace vakata\asn1\test;

use vakata\asn1\ASN1;
use vakata\asn1\Encoder;
use vakata\asn1\Decoder;
use vakata\asn1\structures\Certificate;
use vakata\asn1\structures\CRL;
use vakata\asn1\structures\OCSPRequest;
use vakata\asn1\structures\OCSPResponse;
use vakata\asn1\structures\P7S;
use vakata\asn1\structures\TimestampRequest;
use vakata\asn1\structures\TimestampResponse;

class ASN1Test extends \PHPUnit\Framework\TestCase
{
	public function testEncodeDecode()
	{
		$tsq = [
			'tag' => ASN1::TYPE_SEQUENCE,
			'children' => [
				'version' => [
					'tag' => ASN1::TYPE_INTEGER,
					'map' => [1=>'v1','v2','v3']
				],
				'messageImprint' => [
					'tag' => ASN1::TYPE_SEQUENCE,
					'children' => [
					   'hashAlgorithm' => [
							'tag' => ASN1::TYPE_SEQUENCE,
							'children' => [
								"algorithm" => [
									'tag' => ASN1::TYPE_OBJECT_IDENTIFIER,
									'resolve' => true
								],
								'parameters' => [
									'tag' => ASN1::TYPE_ANY,
									'optional' => true
								]
							]
					   ],
					   'hashedMessage' => [
							'tag' => ASN1::TYPE_OCTET_STRING
					   ]
					]
				],
				'reqPolicy' => [
					'tag' => ASN1::TYPE_OBJECT_IDENTIFIER,
					'optional' => true
				],
				'certReq' => [
					'tag' => ASN1::TYPE_BOOLEAN,
					'optional' => true
				],
				'nonce' => [
					'tag' => ASN1::TYPE_INTEGER,
					'optional' => true
				]
			]
		];

		$src = array(
			'version' => 'v1',
			'messageImprint' => array (
				'hashAlgorithm' => array("algorithm" => 'sha1', 'parameters' => null),
				'hashedMessage' => base64_encode(sha1("asdf", true)),
			),
			'reqPolicy' => null,
			'certReq' => true,
			'nonce' => rand(0, PHP_INT_MAX)
		);

		$res = Encoder::encode($src, $tsq);
		$res = Decoder::fromString($res)->map($tsq);
		$this->assertEquals($src, $res);
	}
	public function testCertificate()
	{
		$this->assertEquals(
			str_replace("\r", "", file_get_contents(__DIR__ . '/samples/certificate.crt.dump')),
			str_replace("\r", "", (string)Certificate::fromFile(__DIR__ . '/samples/certificate.crt'))
		);
	}
	public function testCRL()
	{
		$this->assertEquals(
			str_replace("\r", "", file_get_contents(__DIR__ . '/samples/revocation.crl.dump')),
			str_replace("\r", "", (string)CRL::fromFile(__DIR__ . '/samples/revocation.crl'))
		);
	}
	public function testOCSPRequest()
	{
		$this->assertEquals(
			str_replace("\r", "", file_get_contents(__DIR__ . '/samples/ocsp.req.dump')),
			str_replace("\r", "", (string)OCSPRequest::fromFile(__DIR__ . '/samples/ocsp.req'))
		);
	}
	public function testOCSPResponse()
	{
		$this->assertEquals(
			str_replace("\r", "", file_get_contents(__DIR__ . '/samples/ocsp.res.dump')),
			str_replace("\r", "", (string)OCSPResponse::fromFile(__DIR__ . '/samples/ocsp.res'))
		);
	}
	public function testP7S()
	{
		$this->assertEquals(
			str_replace("\r", "", file_get_contents(__DIR__ . '/samples/signed.p7s.dump')),
			str_replace("\r", "", (string)P7S::fromFile(__DIR__ . '/samples/signed.p7s'))
		);
	}
	public function testTimestampRequest()
	{
		$this->assertEquals(
			str_replace("\r", "", file_get_contents(__DIR__ . '/samples/timestamp.tsq.dump')),
			str_replace("\r", "", (string)TimestampRequest::fromFile(__DIR__ . '/samples/timestamp.tsq'))
		);
	}
	public function testTimestampResponse()
	{
		$this->assertEquals(
			str_replace("\r", "", file_get_contents(__DIR__ . '/samples/timestamp.tsr.dump')),
			str_replace("\r", "", (string)TimestampResponse::fromFile(__DIR__ . '/samples/timestamp.tsr'))
		);
	}
}
