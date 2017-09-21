<?php
/**
 * Affilcore_HawkAuth
 *
 * Class for assembling Hawk auth authorization header
 *
 * @package    Affilcore
 */
class Affilcore_HawkAuth
{
	/**
	 * Hawk protocol version
	 */
	const HEADER_VERSION = 1;

	/**
	 * Hawk key
	 *
	 * @var string
	 */
	private $_key;

	/**
	 * Hawk user id
	 *
	 * @var string
	 */
	private $_userId;

	/**
	 * Hawk ext - optional data to send
	 *
	 * @var string
	 */
	private $_ext;

	/**
	 * Hawk encoding algorithm
	 *
	 * @var string
	 */
	private $_algorithm;


	/**
	 * Constructor
	 *
	 * @param  string $key			- Hawk key
	 * @param  string $userId		- Hawk user id
	 * @param  string $ext			- Optional string to send
	 * @param  string $algorithm	- Encryption algorithm
	 * @return void
	 */
	public function __construct($key, $userId, $ext = '', $algorithm)
	{
		$this->_key = $key;
		$this->_userId = $userId;
		$this->_ext = $ext;
		$this->_algorithm = !empty($algorithm)
			? $algorithm
			: 'sha256';
	}


	/**
	 * Creates fresh Hawk authorization header
	 *
	 * @param  string $hostName		- Hostname of the counterpart
	 * @param  string $method		- Request method to be used
	 * @return void
	 */
	public function generateHeader($hostName, $method = 'POST')
	{
		// TODO: cryptografically weak string
		$nonce = substr(md5(rand()), 0, 6);
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
	 * Creates a Hawk auth mac for use in authorization header
	 *
	 * @param  string $normalized
	 * @return void
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
