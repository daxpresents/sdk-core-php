<?php
//PayPal specific modification starts
//Method to be called for generating signature

class AuthSignature {

	public function genSign($key, $secret, $token, $tokenSecret, $httpMethod, $endpoint) {

		$authServer = new OAuthServer(new MockOAuthDataStore());
		$hmac_method = new OAuthSignatureMethod_HMAC_SHA1();
		$authServer->add_signature_method($hmac_method);

		$sig_method = $hmac_method;
		$authConsumer = new OAuthConsumer($key, $secret, NULL);
		$authToken = NULL;
		$authToken = new OAuthToken($token, $tokenSecret);

		//$params is the query param array which is required only in the httpMethod is "GET"
		$params = array();
		//TODO: set the Query parameters to $params if httpMethod is "GET"

		$acc_req = PPOAuthRequest::from_consumer_and_token($authConsumer, $authToken, $httpMethod, $endpoint, $params);
		$acc_req->sign_request($sig_method,$authConsumer, $authToken);
		return  PPOAuthUtil::parseQueryString($acc_req);
	}

	public static function generateFullAuthString($key, $secret, $token, $tokenSecret, $httpMethod, $endpoint) {
		$authSignature = new AuthSignature();
		$response = $authSignature->genSign($key, $secret, $token, $tokenSecret, $httpMethod, $endpoint);
		return "token=" . $token .
		",signature=" . $response['oauth_signature'] .
		",timestamp=" . $response['oauth_timestamp'];
	}

}
//PayPal specific modification ends
/* Generic exception class
 */
class OAuthException extends Exception {
	// pass
}

class OAuthConsumer {
	public $key;
	public $secret;

	function __construct($key, $secret, $callback_url=NULL) {
		$this->key = $key;
		$this->secret = $secret;
		$this->callback_url = $callback_url;
	}

	function __toString() {
		return "OAuthConsumer[key=$this->key,secret=$this->secret]";
	}
}

class OAuthToken {
	// access tokens and request tokens
	public $key;
	public $secret;

	/**
	 * key = the token
	 * secret = the token secret
	 */
	function __construct($key, $secret) {
		$this->key = $key;
		$this->secret = $secret;
	}

	/**
	 * generates the basic string serialization of a token that a server
	 * would respond to request_token and access_token calls with
	 */
	function to_string() {
		return "oauth_token=" .
		OAuthUtil::urlencode_rfc3986($this->key) .
		"&oauth_token_secret=" .
		OAuthUtil::urlencode_rfc3986($this->secret);
	}

	function __toString() {
		return $this->to_string();
	}
}

/**
 * A class for implementing a Signature Method
 * See section 9 ("Signing Requests") in the spec
 */
abstract class OAuthSignatureMethod {
	/**
	 * Needs to return the name of the Signature Method (ie HMAC-SHA1)
	 * @return string
	 */
	abstract public function get_name();

	/**
	 * Build up the signature
	 * NOTE: The output of this function MUST NOT be urlencoded.
	 * the encoding is handled in OAuthRequest when the final
	 * request is serialized
	 * @param OAuthRequest $request
	 * @param OAuthConsumer $consumer
	 * @param OAuthToken $token
	 * @return string
	 */
	abstract public function build_signature($request, $consumer, $token);

	/**
	 * Verifies that a given signature is correct
	 * @param OAuthRequest $request
	 * @param OAuthConsumer $consumer
	 * @param OAuthToken $token
	 * @param string $signature
	 * @return bool
	 */
	public function check_signature($request, $consumer, $token, $signature) {
		$built = $this->build_signature($request, $consumer, $token);
		return $built == $signature;
	}
}

/**
 * The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104]
 * where the Signature Base String is the text and the key is the concatenated values (each first
 * encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&'
 * character (ASCII code 38) even if empty.
 *   - Chapter 9.2 ("HMAC-SHA1")
 */
class OAuthSignatureMethod_HMAC_SHA1 extends OAuthSignatureMethod {
	function get_name() {
		return "HMAC-SHA1";
	}

	public function build_signature($request, $consumer, $token) {
		$base_string = $request->get_signature_base_string();
		$base_string = preg_replace_callback("/(%[A-Za-z0-9]{2})/", array( $this,'replace_callback'), $base_string);//convert base string to lowercase
		$request->base_string = $base_string;

		$key_parts = array(
			$consumer->secret,
			($token) ? $token->secret : ""
		);

		$key_parts = OAuthUtil::urlencode_rfc3986($key_parts);
		$key = implode('&', $key_parts);
		$key = preg_replace_callback("/(%[A-Za-z0-9]{2})/", array( $this,'replace_callback'), $key);//convert to lowercase
		return base64_encode(hash_hmac('sha1', $base_string, $key, true));
	}
	private function replace_callback($match)
	{
		return strtolower($match[0]);
	}
}

/**
 * The PLAINTEXT method does not provide any security protection and SHOULD only be used
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *   - Chapter 9.4 ("PLAINTEXT")
 */
class OAuthSignatureMethod_PLAINTEXT extends OAuthSignatureMethod {
	public function get_name() {
		return "PLAINTEXT";
	}

	/**
	 * oauth_signature is set to the concatenated encoded values of the Consumer Secret and
	 * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is
	 * empty. The result MUST be encoded again.
	 *   - Chapter 9.4.1 ("Generating Signatures")
	 *
	 * Please note that the second encoding MUST NOT happen in the SignatureMethod, as
	 * OAuthRequest handles this!
	 */
	public function build_signature($request, $consumer, $token) {
		$key_parts = array(
			$consumer->secret,
			($token) ? $token->secret : ""
		);

		$key_parts = OAuthUtil::urlencode_rfc3986($key_parts);
		$key = implode('&', $key_parts);
		$request->base_string = $key;

		return $key;
	}
}

/**
 * The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature algorithm as defined in
 * [RFC3447] section 8.2 (more simply known as PKCS#1), using SHA-1 as the hash function for
 * EMSA-PKCS1-v1_5. It is assumed that the Consumer has provided its RSA public key in a
 * verified way to the Service Provider, in a manner which is beyond the scope of this
 * specification.
 *   - Chapter 9.3 ("RSA-SHA1")
 */
abstract class OAuthSignatureMethod_RSA_SHA1 extends OAuthSignatureMethod {
	public function get_name() {
		return "RSA-SHA1";
	}

	// Up to the SP to implement this lookup of keys. Possible ideas are:
	// (1) do a lookup in a table of trusted certs keyed off of consumer
	// (2) fetch via http using a url provided by the requester
	// (3) some sort of specific discovery code based on request
	//
	// Either way should return a string representation of the certificate
	protected abstract function fetch_public_cert(&$request);

	// Up to the SP to implement this lookup of keys. Possible ideas are:
	// (1) do a lookup in a table of trusted certs keyed off of consumer
	//
	// Either way should return a string representation of the certificate
	protected abstract function fetch_private_cert(&$request);

	public function build_signature($request, $consumer, $token) {
		$base_string = $request->get_signature_base_string();
		$request->base_string = $base_string;

		// Fetch the private key cert based on the request
		$cert = $this->fetch_private_cert($request);

		// Pull the private key ID from the certificate
		$privatekeyid = openssl_get_privatekey($cert);

		// Sign using the key
		$ok = openssl_sign($base_string, $signature, $privatekeyid);

		// Release the key resource
		openssl_free_key($privatekeyid);

		return base64_encode($signature);
	}

	public function check_signature($request, $consumer, $token, $signature) {
		$decoded_sig = base64_decode($signature);

		$base_string = $request->get_signature_base_string();

		// Fetch the public key cert based on the request
		$cert = $this->fetch_public_cert($request);

		// Pull the public key ID from the certificate
		$publickeyid = openssl_get_publickey($cert);

		// Check the computed signature against the one passed in the query
		$ok = openssl_verify($base_string, $decoded_sig, $publickeyid);

		// Release the key resource
		openssl_free_key($publickeyid);

		return $ok == 1;
	}
}

class PPOAuthRequest {
	public $parameters;
	protected $http_method;
	protected $http_url;
	// for debug purposes
	public $base_string;
	public static $version = '1.0';
	public static $POST_INPUT = 'php://input';

	function __construct($http_method, $http_url, $parameters=NULL) {
		$parameters = ($parameters) ? $parameters : array();
		$parameters = array_merge( OAuthUtil::parse_parameters(parse_url($http_url, PHP_URL_QUERY)), $parameters);
		$this->parameters = $parameters;
		$this->http_method = $http_method;
		$this->http_url = $http_url;
	}


	/**
	 * attempt to build up a request from what was passed to the server
	 */
	public static function from_request($http_method=NULL, $http_url=NULL, $parameters=NULL) {
		$scheme = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != "on")
			? 'http'
			: 'https';
		$http_url = ($http_url) ? $http_url : $scheme .
			'://' . $_SERVER['HTTP_HOST'] .
			':' .
			$_SERVER['SERVER_PORT'] .
			$_SERVER['REQUEST_URI'];
		$http_method = ($http_method) ? $http_method : $_SERVER['REQUEST_METHOD'];

		// We weren't handed any parameters, so let's find the ones relevant to
		// this request.
		// If you run XML-RPC or similar you should use this to provide your own
		// parsed parameter-list
		if (!$parameters) {
			// Find request headers
			$request_headers = OAuthUtil::get_headers();

			// Parse the query-string to find GET parameters
			$parameters = OAuthUtil::parse_parameters($_SERVER['QUERY_STRING']);

			// It's a POST request of the proper content-type, so parse POST
			// parameters and add those overriding any duplicates from GET
			if ($http_method == "POST"
				&&  isset($request_headers['Content-Type'])
				&& strstr($request_headers['Content-Type'],
					'application/x-www-form-urlencoded')
			) {
				$post_data = OAuthUtil::parse_parameters(
					file_get_contents(self::$POST_INPUT)
				);
				$parameters = array_merge($parameters, $post_data);
			}

			// We have a Authorization-header with OAuth data. Parse the header
			// and add those overriding any duplicates from GET or POST
			if (isset($request_headers['Authorization']) && substr($request_headers['Authorization'], 0, 6) == 'OAuth ') {
				$header_parameters = OAuthUtil::split_header(
					$request_headers['Authorization']
				);
				$parameters = array_merge($parameters, $header_parameters);
			}

		}

		return new PPOAuthRequest($http_method, $http_url, $parameters);
	}

	/**
	 * pretty much a helper function to set up the request
	 */
	public static function from_consumer_and_token($consumer, $token, $http_method, $http_url, $parameters=NULL) {
		$parameters = ($parameters) ?  $parameters : array();
		$defaults = array("oauth_version" => OAuthRequest::$version,
			// "oauth_nonce" => OAuthRequest::generate_nonce(),
			"oauth_timestamp" => PPOAuthRequest::generate_timestamp(),

			"oauth_consumer_key" => $consumer->key);
		if ($token)
			$defaults['oauth_token'] = $token->key;

		$parameters = array_merge($defaults, $parameters);
		ksort($parameters);
		return new PPOAuthRequest($http_method, $http_url, $parameters);
	}

	public function set_parameter($name, $value, $allow_duplicates = true) {
		if ($allow_duplicates && isset($this->parameters[$name])) {
			// We have already added parameter(s) with this name, so add to the list
			if (is_scalar($this->parameters[$name])) {
				// This is the first duplicate, so transform scalar (string)
				// into an array so we can add the duplicates
				$this->parameters[$name] = array($this->parameters[$name]);
			}

			$this->parameters[$name][] = $value;
		} else {
			$this->parameters[$name] = $value;
		}
	}

	public function get_parameter($name) {
		return isset($this->parameters[$name]) ? $this->parameters[$name] : null;
	}

	public function get_parameters() {
		return $this->parameters;
	}

	public function unset_parameter($name) {
		unset($this->parameters[$name]);
	}

	/**
	 * The request parameters, sorted and concatenated into a normalized string.
	 * @return string
	 */
	public function get_signable_parameters() {
		// Grab all parameters
		$params = $this->parameters;
		ksort($params);
		// Remove oauth_signature if present
		// Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
		if (isset($params['oauth_signature'])) {
			unset($params['oauth_signature']);
		}
		foreach($params as $key => $value)
		{
			$res[]=$key."=".$value;
		}

		return implode('&', $res);
		//return OAuthUtil::build_http_query($params);
	}

	/**
	 * Returns the base string of this request
	 *
	 * The base string defined as the method, the url
	 * and the parameters (normalized), each urlencoded
	 * and the concated with &.
	 */
	public function get_signature_base_string() {
		$parts = array(
			$this->get_normalized_http_method(),
			$this->get_normalized_http_url(),
			$this->get_signable_parameters()
		);

		$parts = OAuthUtil::urlencode_rfc3986($parts);

		return implode('&', $parts);
	}

	/**
	 * just uppercases the http method
	 */
	public function get_normalized_http_method() {
		return strtoupper($this->http_method);
	}

	/**
	 * parses the url and rebuilds it to be
	 * scheme://host/path
	 */
	public function get_normalized_http_url() {
		$parts = parse_url($this->http_url);

		$scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
		$port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : '80');
		$host = (isset($parts['host'])) ? $parts['host'] : '';
		$path = (isset($parts['path'])) ? $parts['path'] : '';

		if (($scheme == 'https' && $port != '443')
			|| ($scheme == 'http' && $port != '80')) {
			$host = "$host:$port";
		}
		return "$scheme://$host$path";
	}

	/**
	 * builds a url usable for a GET request
	 */
	public function to_url() {
		$post_data = $this->to_postdata();
		$out = $this->get_normalized_http_url();
		if ($post_data) {
			$out .= '?'.$post_data;
		}
		return $out;
	}

	/**
	 * builds the data one would send in a POST request
	 */
	public function to_postdata() {
		return OAuthUtil::build_http_query($this->parameters);
	}

	/**
	 * builds the Authorization: header
	 */
	public function to_header($realm=null) {
		$first = true;
		if($realm) {
			$out = 'Authorization: OAuth realm="' . OAuthUtil::urlencode_rfc3986($realm) . '"';
			$first = false;
		} else
			$out = 'Authorization: OAuth';

		$total = array();
		foreach ($this->parameters as $k => $v) {
			if (substr($k, 0, 5) != "oauth") continue;
			if (is_array($v)) {
				throw new OAuthException('Arrays not supported in headers');
			}
			$out .= ($first) ? ' ' : ',';
			$out .= OAuthUtil::urlencode_rfc3986($k) .
				'="' .
				OAuthUtil::urlencode_rfc3986($v) .
				'"';
			$first = false;
		}
		return $out;
	}

	public function __toString() {
		return $this->to_url();
	}


	public function sign_request($signature_method,$consumer, $token) {

		$empty=false;
		$msg=array();
		if( $token->key==null){
			$msg[] = 'Token key';
		}
		if($token->secret==null){
			$msg[] = 'Token secret';
		}
		if($consumer->key == null){

			$msg[] = 'Consumer key';
		}
		if($consumer->secret == null){

			$msg[] = 'Consumer secret';
		}
		if($this->http_url == null){

			$msg[] ='Endpoint';
		}
		if($this->http_method == null){

			$msg[] ='HTTP method';
		}
		if(count($msg))
		{
			throw new OAuthException('Enter valid '. implode(',',$msg));
		}
		$this->set_parameter(
			"oauth_signature_method",
			$signature_method->get_name(),
			false );

		$signature = $this->build_signature($signature_method, $consumer, $token);
		$this->set_parameter("oauth_signature", $signature, false);

	}

	public function build_signature($signature_method, $consumer, $token) {
		$signature = $signature_method->build_signature($this, $consumer, $token);
		return $signature;
	}

	/**
	 * util function: current timestamp
	 */
	private static function generate_timestamp() {
		return time();
	}

	/**
	 * util function: current nonce
	 */
	private static function generate_nonce() {
		$mt = microtime();
		$rand = mt_rand();

		return md5($mt . $rand); // md5s look nicer than numbers
	}
}

class PPOAuthUtil {
	public static function urlencode_rfc3986($input) {
		if (is_array($input)) {
			return array_map(array('OAuthUtil', 'urlencode_rfc3986'), $input);
		} else if (is_scalar($input)) {
			$tmp1=str_replace('%7E', '~', rawurlencode($input));
			$tmp2=str_replace(".","%2E",$tmp1);
			$tmp3=str_replace("*","%2A",$tmp2);
			$tmp4=str_replace( '+', ' ',$tmp3);
			$tmp=str_replace("-","%2D",$tmp4);
			return $tmp;
			/*$tmp1=str_replace('%7E', '~', rawurlencode($input));
			 $tmp2= str_replace(".","%2E",$tmp1);


			 return $tmp;*/
		}
		else {
			return '';
		}
	}
	public static function parseQueryString($str) {
		$op = array();
		$pairs = explode("&", $str);
		foreach ($pairs as $pair) {
			list($k, $v) = array_map("urldecode", explode("=", $pair));
			$op[$k] = $v;
		}
		return $op;
	}

}