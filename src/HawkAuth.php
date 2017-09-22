<?php

namespace helvete\Tools;

class HawkAuth {

	const HEADER_VERSION = 1;

	/** @var string */
	private $_key;

	/** @var string */
	private $_userId;

	/** @var string */
	private $_ext;

	/** @var string */
	private $_algorithm;

	/**
	 * Construct
	 *
	 * @param  string		$key
	 * @param  string		$userId
	 * @param  string		$ext
	 * @param  string|null	$algorithm
	 */
	public function __construct($key, $userId, $ext = '', $algorithm = null)
	{
		$this->_key = $key;
		$this->_userId = $userId;
		$this->_ext = $ext;
		$this->_algorithm = !empty($algorithm)
			? $algorithm
			: 'sha256';
	}


	/**
	 * Create fresh Hawk authorization header
	 *
	 * @param  string	$hostName
	 * @param  string	$method
	 * @return string
	 */
	public function generateHeader($hostName, $method = 'POST')
	{
		$nonce = bin2hex(openssl_random_pseudo_bytes(3));
		$timestamp = time();

		$attributes = parse_url($hostName);

		$normalized = 'hawk.' . self::HEADER_VERSION . ".header\n"
			. $timestamp . "\n"
			. $nonce . "\n"
			. strtoupper($method) . "\n"
			. $attributes['path'] . "\n"
			. strtolower($attributes['host']) ."\n"
			. $attributes['port'] . "\n"
			. null . "\n"
			. $this->_ext . "\n";

		// assign 'ext' part of the header if present
		$extHeaderPart = empty($this->_ext)
			? ''
			: '", ext="' . $this->_ext;

		return 'Hawk id="' . $this->_userId
			. '", ts="' . $timestamp
			. '", nonce="' . $nonce
			. $extHeaderPart
			. '", mac="'
			. $this->_getMac($normalized)
			. '"';
	}


	/**
	 * Create a Hawk auth mac for use in authorization header
	 *
	 * @param  string	$normalized
	 * @return string
	 */
	private function _getMac($normalized)
	{
		return base64_encode(hash_hmac(
			$this->_algorithm,
			$normalized,
			$this->_key,
			true
		));
	}
}
