<?php
namespace vakata\asn1\test;

use vakata\asn1\ASN1;

class ASN1Test extends \PHPUnit_Framework_TestCase
{
	public function testEncodeDecode() {
		$tsq = [
			'tag' => ASN1::TYPE_SEQUENCE,
			'children' => [
				'version' => [
					'tag' => ASN1::TYPE_INTEGER,
					'mapping' => [1=>'v1','v2','v3']
				],
				'messageImprint' => [
					'tag' => ASN1::TYPE_SEQUENCE,
					'children' => [
					   'hashAlgorithm' => [
							'tag' => ASN1::TYPE_SEQUENCE,
							'children' => [
								"algorithm" => [
									'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
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
				'nonce' => [
					'tag' => ASN1::TYPE_INTEGER,
					'optional' => true
				],
				'certReq' => [
					'tag' => ASN1::TYPE_BOOLEAN,
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

		$res = ASN1::encodeDER($src, $tsq);
		$res = ASN1::decodeDER($res, $tsq);
		$this->assertEquals($src, $res);
	}
}
