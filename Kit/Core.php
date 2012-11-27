<?php
/**
 * PHP toolkit for fast prototyping of web applications and API's
 *
 * Main features include: Database, Validation, Session Handling, Routing,
 * Response, SMTP Email, Encryption, Request parsing, OAuth2 support,
 * Internationalization, Unicode conversion, and View Inheritance.
 *
 * TL;DR Does 90% of everything you need to build a web app
 *
 * @author 		David Pennington
 * @copyright	(c) 2012 davidpennington.me
 * @license		MIT License <http://www.opensource.org/licenses/mit-license.php>
 ********************************** 80 Columns *********************************
 */
namespace Kit; // The one and only

// The full schema, TLD address, and port
define('KIT\URL_HOST', (strtolower(getenv('HTTPS')) == 'on' ? 'https' : 'http')
	. '://' . getenv('HTTP_HOST')
	. (($p = getenv('SERVER_PORT')) != 80 AND $p != 443 ? ":$p" : ''));

//* Use the CLI argument or decode the URL path taking unicode into account
define('KIT\URL_PATH', isset($argv[1])
	? $argv[1] : rawurldecode(trim(parse_url(getenv('REQUEST_URI'), PHP_URL_PATH), '/')));

// What filetype are they expecting? (json, xml, or html?)
define('KIT\URL_TYPE', (preg_match('~\.([a-z]{3,4})($|\?)~', URL_PATH, $match)
	? $match[1] : NULL));

// What is the ISO 639-1 language code at the start of the URL path?
define('KIT\URL_LANGUAGE', (preg_match('~^([a-z]{2})/~', URL_PATH, $match)
	? $match[1] : 'en'));

// Is this an AJAX request? (jQuery, Mootools, YUI, Dojo, etc...)
define('KIT\IS_AJAX_REQUEST', strtolower(getenv('HTTP_X_REQUESTED_WITH')) === 'xmlhttprequest');

// Is this a mobile request? (Android, iOS, Blackberry, and Mobile Opera)
define('KIT\IS_MOBILE_REQUEST', (bool) preg_match('~(Mobi)|(webOS)|(Android)~', getenv('HTTP_USER_AGENT')));

// Standardize request method: GET, POST, PUT, DELETE, HEAD, or CLI 
define('KIT\REQUEST_METHOD', PHP_SAPI == 'cli' ? 'CLI' : 
	in_array(getenv('REQUEST_METHOD'), array('GET', 'POST', 'PUT', 'DELETE', 'HEAD'))
	? getenv('REQUEST_METHOD') : 'GET');

/**
 * Return the full URL to a location on this site. In PHP 5.4, http_build_query
 * will finally support RFC 3986 so we can remove that `str_replace()` code.
 *
 * @param string $path to use or FALSE for current path
 * @param array $params to append to URL
 * @return string
 */
function site_url($path = NULL, array $params = NULL)
{
	// http://, ftp://, and even "//example.com/asset.js" are all valid URL's.
	if(strpos($path, '//') === FALSE)
	{
		$path = URL_HOST . '/' . trim($path, '/');
	}

	return $path . ($params ? '?'. str_replace('+', '%20', http_build_query($params, TRUE, '&')) : '');
}

/**
 * Color string output for the CLI using standard color codes.
 *
 * @param string $text to color
 * @param string $color of text
 * @param string $bold True to bold the text
 */
function color_cli($text, $color, $bold = FALSE)
{
	$colors = array_flip(array(
		30 => 'gray', 'red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'white', 'black'
	));

	return "\033[" . ($bold ? '1' : '0') . ';' . $colors[$color] . "m$text\033[0m";
}

/**
 * Safely fetch a $_POST value by key name
 *
 * @param string $key
 * @param mixed $default
 * @return mixed
 */
function post($key, $default = NULL)
{
	return isset($_POST[$key]) ? $_POST[$key] : $default;
}

/**
 * Safely fetch a $_GET value by key name
 *
 * @param string $key
 * @param mixed $default
 * @return mixed
 */
function get($key, $default = NULL)
{
	return isset($_GET[$key]) ? $_GET[$key] : $default;
}

/**
 * Safely fetch a $_SESSION value by key name
 *
 * @param string $key
 * @param mixed $default
 * @return mixed
 */
function session($key, $default = NULL)
{
	return isset($_SESSION[$key]) ? $_SESSION[$key] : $default;
}

/**
 * HTML encode special characters so string is safe for display
 *
 * @param string $string
 * @return string
 */
function h($string)
{
	return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

/**
 * Return a formatted variable dump of the given arguments
 *
 * @param mixed
 * @return string
 */
function dump()
{
	$output = '';
	foreach (func_get_args() as $argument)
	{
		if (is_resource($argument) === true)
		{
			$result = sprintf('%s (#%u)', 
				get_resource_type($argument), $argument);
		}

		else if ((is_array($argument) === true) || (is_object($argument) === true))
		{
			$result = rtrim(print_r($argument, true));
		}

		else
		{
			$result = stripslashes(
				preg_replace("~^'|'$~", '', var_export($argument, true))
			);
		}

		if (PHP_SAPI !== 'cli')
		{
			$result = '<pre style="margin: 1em;padding: 1em;text-align: left;">' . h($result) . '</pre>';
		}

		$output .= $result . "\n\n";
	}
	return $output;
}


/**
 * Provides a database wrapper around the PDO service to help reduce the effort
 * to interact with a RDBMS such as SQLite, MySQL, or PostgreSQL.
 */
class DB
{
	public $i, $c, $driver;
	static $queries = array();

	/**
	 * Set the database connection on creation. This allows us to use
	 * [dependency injection](http://en.wikipedia.org/wiki/Dependency_injection)
	 * to support multiple database wrappers to different RDBMS.
	 *
	 * @param object $pdo PDO connection object
	 */
	public function __construct(\PDO $pdo)
	{
		$this->c = $pdo;
		$this->driver = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);

		switch($this->driver)
		{
			case 'pgsql':
			case 'sqlsrv':
			case 'dblib':
			case 'mssql':
			case 'sybase':
				$this->i = '"';
				break;
			case 'mysql':
			case 'sqlite':
			case 'sqlite2':
			default:
				$this->i = '`';
		}
	}


	/**
	 * Escapes dangerous characters in string so it can be used in a raw SQL
	 * query. Instead of quoting values it is recomended that you use prepared
	 * statements.
	 *
	 * @param mixed $value to quote
	 * @return string
	 */
	public function quote($value)
	{
		return $this->c->quote($value);
	}

	/**
	 * Fetch a column offset from the result set (COUNT() queries)
	 *
	 * @param string $query query string
	 * @param array $params query parameters
	 * @param integer $key index of column offset
	 * @return array|null
	 */
	public function column($query, $params = NULL, $key = 0)
	{
		if($statement = $this->query($query, $params))
			return $statement->fetchColumn($key);
	}

	/**
	 * Fetch a single query result row
	 *
	 * @param string $query query string
	 * @param array $params query parameters
	 * @return mixed
	 */
	public function row($query, $params = NULL)
	{
		if($statement = $this->query($query, $params))
			return $statement->fetch();
	}

	/**
	 * Fetches an associative array of all rows as key-value pairs (first
	 * column is the key, second column is the value).
	 *
	 * @param string $query query string
	 * @param array $params query parameters
	 * @return array
	 */
	public function pairs($query, $params = NULL)
	{
		$data = array();

		if($statement = $this->query($query, $params))
			while($row = $statement->fetch(\PDO::FETCH_NUM))
				$data[$row[0]] = $row[1];

		return $data;
	}

	/**
	 * Fetch all query result rows
	 *
	 * @param string $query query string
	 * @param array $params query parameters
	 * @param int $column the optional column to return
	 * @return array
	 */
	public function fetch($query, $params = NULL, $column = NULL)
	{
		if( ! $statement = $this->query($query, $params)) return;

		// Return an array of records
		if($column === NULL) return $statement->fetchAll();

		// Fetch a certain column from all rows
		return $statement->fetchAll(\PDO::FETCH_COLUMN, $column);
	}

	/**
	 * Prepare and send a query returning the PDOStatement
	 *
	 * @param string $query query string
	 * @param array $params query parameters
	 * @return object|null
	 */
	public function query($query, $params = NULL)
	{
		$statement = $this->c->prepare(static::$queries[] = strtr($query, '`', $this->i));
		$statement->execute( (array) $params);
		return $statement;
	}

	/**
	 * Insert a row into the database
	 *
	 * @param string $table name
	 * @param array $data
	 * @param string $column The name of the primary key column
	 * @return integer|null
	 */
	public function insert($table, array $data, $column = 'id')
	{
		$query = "INSERT INTO `$table` (`" . implode('`, `', array_keys($data))
			. '`) VALUES (' . rtrim(str_repeat('?, ', count($data = array_values($data))), ', ') . ')';

		return $this->driver == 'pgsql'
			? $this->column($query . " RETURNING `$column`", $data)
			: ($this->query($query, $data) ? $this->c->lastInsertId() : NULL);
	}

	/**
	 * Update a database row
	 *
	 * @param string $table name
	 * @param array $data
	 * @param integer $pk The primary key
	 * @param string $column The name of the primary key column
	 * @return integer|null
	 */
	public function update($table, $data, $pk, $column = 'id')
	{
		$keys = implode('`= ?, `', array_keys($data));
		$query = "UPDATE `$table` SET `$keys` = ? WHERE `$column` = ?";

		if($statement = $this->query($query, array_values($data + array($pk))))
		{
			return $statement->rowCount();
		}
	}

	/**
	 * Issue a delete query
	 *
	 * @param string $table name
	 * @param integer $pk The primary key
	 * @param string $column The name of the primary key column
	 * @return integer|null
	 */
	function delete($table, $pk, $column = 'id')
	{
		if($statement = $this->query("DELETE FROM `$table` WHERE `$column` = ?", $pk))
		{
			return $statement->rowCount();
		}
	}
}


/**
 * Core Kit bootstrap class to setup system defaults (if wanted)
 */
class Core
{
	/**
	 * Define common system defaults
	 */
	public function defaults()
	{
		// A stream should respond to a connection attempt within ten seconds
		ini_set('default_socket_timeout', 10);

		// iconv encoding default
		iconv_set_encoding("internal_encoding", "UTF-8");

		// Multibyte encoding
		mb_internal_encoding('UTF-8');

		// Don't show SimpleXML/DOM errors (most of the web is invalid)
		libxml_use_internal_errors(true);

		// Please sir - use GMT instead of UTC for poor little MySQL's sake!
		date_default_timezone_set('GMT');
	}

	/**
	 * Filter all input to insure everything is valid unicode
	 */
	public function filterInput()
	{
		// Convert all input to valid, UTF-8 strings with no control characters
		$_GET = \Kit\I18n::filter($_GET, false);
		$_POST = \Kit\I18n::filter($_POST, false);
		$_COOKIE = \Kit\I18n::filter($_COOKIE, false);
	}

	/**
	 * Create root-level aliases for all classes defined in our Kit
	 */
	public function aliasClasses()
	{
		class_alias('\Kit\DB', 'DB');
		class_alias('\Kit\Cipher', 'Cipher');
		class_alias('\Kit\Cookie', 'Cookie');
		class_alias('\Kit\Event', 'Event');
		class_alias('\Kit\I18n', 'I18n');
		class_alias('\Kit\Instance', 'Instance');
		class_alias('\Kit\Login', 'Login');
		class_alias('\Kit\OAuth2', 'OAuth2');
		class_alias('\Kit\Response', 'Response');
		class_alias('\Kit\Router', 'Router');
		class_alias('\Kit\Session', 'Session');
		class_alias('\Kit\SMTP', 'SMTP');
		class_alias('\Kit\Table', 'Table');
		class_alias('\Kit\Validator', 'Validator');
		class_alias('\Kit\View', 'View');
	}
}

/**
 * Ciphers algorithms for encription, hashing, and base conversion
 */
class Cipher
{
	/**
	 * Encrypt a string
	 *
	 * @param string $string to encrypt
	 * @param string $key a cryptographically random string
	 * @param int $algo the encryption algorithm
	 * @param int $mode the block cipher mode
	 * @return string
	 */
	public static function encrypt($string, $key, $algo = MCRYPT_RIJNDAEL_256, $mode = MCRYPT_MODE_CBC)
	{
		$iv = mcrypt_create_iv(mcrypt_get_iv_size($algo, $mode), MCRYPT_DEV_URANDOM);
		return base64_encode(mcrypt_encrypt($algo, $key, $string, $mode, $iv) . $iv);
	}

	/**
	 * Decrypt an encrypted string
	 *
	 * @param string $string to encrypt
	 * @param string $key a cryptographically random string
	 * @param int $algo the encryption algorithm
	 * @param int $mode the block cipher mode
	 * @return string
	 */
	public static function decrypt($string, $key, $algo = MCRYPT_RIJNDAEL_256, $mode = MCRYPT_MODE_CBC)
	{
		$string = base64_decode($string);
		$size = mcrypt_get_iv_size($algo, $mode);
		$iv = substr($string, -$size);
		if(strlen($iv) === $size)
		{
			return rtrim(mcrypt_decrypt($algo, $key, substr($string, 0, -$size), $mode, $iv), "\x0");
		}
	}

	/**
	 * Hash a string using blowfish with a default of 12 iterations. To verify a hash,
	 * pass the hash plus the string back to this function as the second parameter.
	 *
	 * @param string $string to hash
	 * @param string|null $salt previous hash of string
	 * @return string
	 */
	public static function hash($string, $salt = NULL, $iterations = '12')
	{
		$hash = crypt($string, $salt ?: "$2a\$$iterations$" . md5(mcrypt_create_iv(22, MCRYPT_DEV_URANDOM)));
		if (strlen($hash) == 60) return $hash;
	}

	/**
	 * Convert a higher-base ID key back to a base-10 integer
	 *
	 * @param string $key
	 * @return integer
	 */
	public static function keyToID($key)
	{
		return function_exists('gmp_init') ? gmp_strval(gmp_init($key, 62), 10) : base_convert($key, 32, 10);
	}

	/**
	 * Convert a base-10 integer to a higher-base ID key
	 *
	 * @param integer $id
	 * @return string
	 */
	public static function IDToKey($id)
	{
		return function_exists('gmp_init') ? gmp_strval(gmp_init($id, 10), 62) : base_convert($key, 10, 32);
	}

	/**
	 * Encode a string so it is safe to pass through the URL
	 *
	 * @param string $string to encode
	 * @return string
	 */
	public static function base64_url_encode($string = NULL)
	{
		return strtr(base64_encode($string), '+/=', '-_~');
	}

	/**
	 * Decode a string passed through the URL
	 *
	 * @param string $string to decode
	 * @return string
	 */
	public static function base64_url_decode($string = NULL)
	{
		return base64_decode(strtr($string, '-_~', '+/='));
	}
}

/**
 * Handle reading and writing encrypted cookies
 */
class Cookie
{
	/**
	 * Decrypt and fetch cookie data as long as the cookie has not expired
	 *
	 * @param string $name of cookie
	 * @param array $config settings
	 * @return mixed
	 */
	public static function get($name, $config = NULL)
	{
		if(isset($_COOKIE[$name]))
		{
			if($value = json_decode(Cipher::decrypt($_COOKIE[$name], $config['key']), TRUE))
			{
				if($value[0] < (time() + $config['timeout']))
				{
					return $value[1];
				}
			}
		}

		return FALSE;
	}

	/**
	 * Called before any output is sent to create an encrypted cookie with the given value.
	 *
	 * @param string $key cookie name
	 * @param mixed $value to save
	 * @param array $config settings
	 * return boolean
	 */
	public static function set($name, $value, $config)
	{
		extract($config);

		// If the cookie is being removed we want it left blank
		if($value)
		{
			$value = Cipher::encrypt(json_encode(array(time(), $value)), $key);
		}

		// Update the current cookie global
		$_COOKIE[$name] = $value;

		// Save cookie to user agent
		setcookie($name, $value, $expires, $path, $domain, $secure, $httponly);
	}

}

/**
 * Provide an observer-based event system making it easier to tie into existing functionality
 */
class Event
{
	protected static $listeners = array();

	public static function on($event, \Closure $listener)
	{
		static::$listeners[$event][] = $listener;
	}
	
	public static function once($event, \Closure $listener)
	{
		$onceListener = function () use (&$onceListener, $event, $listener)
		{
			static::off($event, $onceListener);
			call_user_func_array($listener, func_get_args());
		};

		static::on($event, $onceListener);
	}

	public static function off($event, \Closure $listener)
	{
		if (isset(static::$listeners[$event]))
		{
			if (false !== $index = array_search($listener, static::$listeners[$event], true))
			{
				unset(static::$listeners[$event][$index]);
			}
		}
	}

	public static function removeAllListeners($event = null)
	{
		if ($event !== null) {
			unset(static::$listeners[$event]);
		} else {
			static::$listeners = array();
		}
	}

	public static function listeners($event)
	{
		return isset(static::$listeners[$event]) ? static::$listeners[$event] : array();
	}

	public static function emit($event, $parameters = NULL)
	{
		$parameters = func_get_args();
		array_shift($parameters);

		foreach (self::listeners($event) as $listener)
		{
			$result = call_user_func_array($listener, $parameters);
				
			if($result !== NULL)
			{
				$parameters = $result;
			}
		}

		return $parameters;
	}
}

/**
 * Handles doing all the i18n and l10n stuff PHP should already do.
 * Basically, makes your site work with other languages.
 *
 * Much of this class comes from the groundbreaking work of Alix Axel
 * @see https://github.com/alixaxel/phunction
 */
//class Internationalization
class I18n
{
	/**
	 * Set the default locale for this request
	 *
	 * @param string $locale The locale desired
	 */
	public static function setLocale($locale)
	{
		// Match preferred language to those available, defaulting to generic English
		$locale = Locale::lookup(config()->languages, $locale, false, 'en');
		Locale::setDefault($locale);
		setlocale(LC_ALL, $locale . '.utf-8');
		//putenv("LC_ALL", $locale);
	}

	/**
	 * Format the given string using the current system locale.
	 * Basically, it's sprintf on i18n steroids.
	 *
	 * @see MessageFormatter
	 * @param string $string to parse
	 * @param array $params to insert
	 * @return string
	 */
	public static function format($string, array $params = NULL)
	{
		return msgfmt_format_message(setlocale(LC_ALL,0), $string, $params);
	}

	/**
	 * Format the given DateTime object (or string) for display in the current locale
	 *
	 * @param DateTime $date
	 * @param integer $datetype
	 * @param integer $typetype
	 * @param integer $timezone
	 * @return string
	 */
	public static function date($date, $datetype = IntlDateFormatter::MEDIUM, $timetype = IntlDateFormatter::SHORT, $timezone = NULL)
	{
		$dateFormatter = new IntlDateFormatter(
			Locale::getDefault(),
			$datetype,
			$timetype,
			$timezone ?: date_default_timezone_get()
		);

		if( ! $date instanceof \DateTime)
		{
			$date = new DateTime('@' . strtotime($date));
		}

		return $dateFormatter->format($date->getTimestamp());
	}

	/**
	 * Convert an integer to a PHP timezone name
	 *
	 * @param integer $offset
	 * @param boolean $dst
	 * @return string
	 */
	public static function utc_offset_to_timezone($offset, $dst = false)
	{
		return timezone_name_from_abbr('', (int) $offset * 3600, $dst);
	}

	/**
	 * Normalize the given UTF-8 string
	 *
	 * @see http://stackoverflow.com/a/7934397/99923
	 * @param string $string to normalize
	 * @param int $form to normalize as
	 * @return string
	 */
	public static function normalize($string, $form = Normalizer::FORM_KD)
	{
		return normalizer_normalize($string, $form);
	}

	/**
	 * Convert a string to UTF-8, remove invalid bytes sequences, and control
	 * characters.
	 *
	 * @param string $string to convert
	 * @param string $control true to remove control characters
	 * @param string $encoding current encoding of string (default to UTF-8)
	 * @return string
	 */
	public static function filter($data, $control = true, $encoding = null)
	{
		if (is_array($data) === true)
		{
			$result = array();

			foreach ($data as $key => $value)
			{
				$result[self::filter($key, $control, $encoding)] = self::filter($value, $control, $encoding);
			}

			return $result;
		}

		else if (is_string($data) === true)
		{
			if (preg_match('~[^\x00-\x7F]~', $data) > 0)
			{
				if (function_exists('mb_detect_encoding') === true)
				{
					$encoding = mb_detect_encoding($data, 'auto');
				}

				$data = @iconv((empty($encoding) === true) ? 'UTF-8' : $encoding, 'UTF-8//IGNORE', $data);
			}

			// ~\R~u  ====  ~\r\n?~		???
			return ($control === true) ? preg_replace('~\p{C}+~u', '', $data) : preg_replace(array('~\r\n?~', '~[^\P{C}\t\n]+~u'), array("\n", ''), $data);
		}

		return $data;
	}

	/**
	 * Remove accents from characters
	 *
	 * @param string $string to remove accents from
	 * @return string
	 */
	public static function unaccent($string)
	{
		if (strpos($string = htmlentities($string, ENT_QUOTES, 'UTF-8'), '&') !== false)
		{
			$regex = '~&([a-z]{1,2})(?:acute|caron|cedil|circ|grave|lig|orn|ring|slash|tilde|uml);~i';
			$string = html_entity_decode(preg_replace($regex, '$1', $string), ENT_QUOTES, 'UTF-8');
		}

		return $string;
	}

	/**
	 * Convert a string to an ASCII/URL/file name safe slug
	 *
	 * @param string $string to convert
	 * @param string $slug character to separate words with
	 * @param string $extra characters to include
	 * @return string
	 */
	public static function slug($string, $slug = '-', $extra = null)
	{
		$string = self::unaccent(self::normalize($string));
		return strtolower(trim(preg_replace('~[^0-9a-z' . preg_quote($extra, '~') . ']+~i', $slug, $string), $slug));
	}

	/**
	 * Tests whether a string contains only 7bit ASCII characters.
	 *
	 * @param string $string to check
	 * @return bool
	 */
	public static function is_ascii($string)
	{
		return ! preg_match('/[^\x00-\x7F]/S', $string);
	}
}

/**
 * Dependency Injection + Service Locator
 */
class Instance {

	public static $registry = array();

	public static function register($name, \Closure $resolver)
	{
		static::$registry[$name] = $resolver;
	}

	public static function registered($name)
	{
		return isset(static::$registry[$name]);
	}

	public static function get($name, $parameters = NULL)
	{
		if ( ! static::registered($name))
		{
			throw new \Exception("Error resolving [$name]. No resolver has been registered.");
		}

		if(static::$registry[$name] instanceof \Closure)
		{
			static::$registry[$name] = call_user_func(static::$registry[$name], $parameters);
		}

		return static::$registry[$name];
	}
}

/**
 * Provide basic wrapper around login services
 */
class Login
{
	/**
	 * Verify a BrowserID assertion and return the user object
	 *
	 * @param string $assertion
	 * @param string $host
	 * @return array|null
	 */
	public static function browserID($assertion, $host = NULL)
	{
		/*
		curl_setopt_array($h = curl_init('https://verifier.login.persona.org/verify'),array(
			CURLOPT_RETURNTRANSFER=>1,
			CURLOPT_POST=>1,
			CURLOPT_POSTFIELDS=>"assertion=$assertion&audience=" . ($host ?: 'http://'. getenv('HTTP_HOST'))
		));

		return json_decode(curl_exec($h));
		*/

		$c = stream_context_create(array('http' => array(
			'method' => 'POST',
			'header' => 'Content-type: application/x-www-form-urlencoded',
			'content'=> "assertion=$assertion&audience=" . ($host ?: 'http://'. getenv('HTTP_HOST')),
			//'ignore_errors' => true
		)));

		$data = file_get_contents('https://verifier.login.persona.org/verify', 0, $c);

		if($data AND ($data = json_decode($data, true)))
		{
			return $data;
		}
	}

	/**
	 * Verify and require a valid HTTP Digest Auth login
	 *
	 * @param array $users in array(user => password) form
	 * @param string $realm shown in auth box
	 * @param boolean $exit
	 * @return boolean
	 */
	function hmac_http_auth(array $users, $realm = "Secured Area", $exit = TRUE)
	{
		if( ! empty($_SERVER['PHP_AUTH_DIGEST']))
		{
			// Decode the data the client gave us
			$default = array('nounce', 'nc', 'cnounce', 'qop', 'username', 'uri', 'response');
			preg_match_all('~(\w+)="?([^",]+)"?~', $_SERVER['PHP_AUTH_DIGEST'], $matches);
			$data = array_combine($matches[1] + $default, $matches[2]);

			// Generate the valid response
			$A1 = md5($data['username'] . ':' . $realm . ':' . $users[$data['username']]);
			$A2 = md5(getenv('REQUEST_METHOD').':'.$data['uri']);
			$valid_response = md5($A1.':'.$data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'].':'.$A2);

			// Compare with what was sent
			if($data['response'] === $valid_response)
			{
				return TRUE;
			}
		}

		if( ! $exit) return FALSE;

		// Failed, or haven't been prompted yet
		header('HTTP/1.1 401 Unauthorized');
		header('WWW-Authenticate: Digest realm="' . $realm.
			'",qop="auth",nonce="' . uniqid() . '",opaque="' . md5($realm) . '"');
		exit();
	}
}

/**
 * Perform OAuth 2.0 authorization against service providers
 */
class OAuth2
{
	public $client_id, $client_secret, $auth_url, $token_url;

	/**
	 * Create a new OAuth2 instance
	 *
	 * @param array $config
	 * @param bool $debug
	 */
	public function __construct($config, $debug = false)
	{
		foreach($config as $key => $value)
		{
			$this->$key = $value;
		}

		$this->debug = $debug;
	}

	/**
	 * Request an access token for the given service
	 *
	 * @param string $redirect_uri
	 * @param string $code
	 * @param string $state
	 * @param string $scope
	 * @return array
	 */
	public function getToken($redirect_uri, $code, $state, $scope = '')
	{
		$params = array(
			'client_id' => $this->client_id,
			'redirect_uri' => $redirect_uri,
			'scope' => $scope,
			'state' => $state
		);

		if($code)
		{
			$params = http_build_query($params + array(
				'client_secret' => $this->client_secret,
				'grant_type' => 'authorization_code',
				'code' => $code,
			));

			$c = stream_context_create(array('http' => array(
				'method'  => 'POST',
				'header'  => 'Content-type: application/x-www-form-urlencoded\r\nContent-Length: ' . strlen($params),
				'content' => $params,
				'ignore_errors' => $this->debug == TRUE
			)));

			if($result = file_get_contents($this->token_url . '?' . $params, 0, $c))
			{
				if($this->debug)
				{
					return join("\n", $http_response_header) . "\n\n" . $result;
				}

				if($json = json_decode($result))
				{
					return $json;
				}

				parse_str($result, $pieces);
				return $pieces;
			}
		}
		else
		{
			$params['response_type'] = 'code';
			header("Location: " . $this->auth_url . '?' . http_build_query($params), TRUE, 307);
			die();
		}
	}
}

/**
 * Send a response to client
 */
class Response
{
	static $mode = PHP_SAPI;

	/**
	 * HTTP Response Statuses
	 *
	 * Uncommon or server-level statuses are not included
	 */
	const OK = '200 OK';
	const CREATED = '201 Created';
	const MOVED_PERM = '301 Moved Permanently';
	const MOVED_TEMP = '302 Found';
	const REDIRECT = '307 Temporary Redirect';
	const BAD_REQUEST = '400 Bad Request';
	const FORBIDDEN = '403 Forbidden';
	const NOT_FOUND = '404 Not Found';
	const METHOD_NOT_ALLOWED = '405 Method Not Allowed';
	const SERVER_ERROR = '500 Internal Server Error';

	/**
	 * Send the status, response headers, and body - then end the script
	 *
	 * @param string $status
	 * @param array $headers
	 * @param string $body
	 */
	public static function send($status, $body = '', array $headers = array())
	{
		list($status, $headers, $body) = Event::emit('response.send', $status, $headers, $body);

		if ( ! headers_sent() AND static::$mode != 'cli')
		{
			// @todo Remove all cookie headers to fix double session-cookie bug
			header('Set-Cookie: ', true);
			
			// Send status header
			header((getenv('SERVER_PROTOCOL') ?: 'HTTP/1.1') . ' ' . $status);

			// Send all stored headers
			foreach ($headers as $type => $value)
			{
				header($type . ': ' . $value, TRUE);
			}
		}

		print $body;
	}

	/**
	 * Issue a redirect to the user agent
	 *
	 * @param string $url
	 * @param array $params
	 */
	public static function redirect($url, array $params = NULL)
	{
		list($url, $params) = Event::emit('response.redirect', $url, $params);
		Response::send(Response::REDIRECT, '', array('Location' => site_url($url, $params)));
	}
}

/**
 * Route request to the correct closure callbacks using regex path matching
 */
class Router
{
	public $controller, $params, $path, $method;

	/**
	 * Create a new router instance
	 *
	 * @param string $method
	 * @param string $path
	 */
	public function __construct($method = REQUEST_METHOD, $path = URL_PATH)
	{
		$this->method = $method;
		$this->path = $path;
	}

	/**
	 * Map the given route to a controller closure. The route parser is much smater than
	 * it looks and does not need regex submatches to find and pass URL params to the
	 * closure callback. Regex routes are automatically wrapped with tides (~).
	 *
	 * @param string $method The type of request method this route is valid for
	 * @param string $route The regex route to match
	 * @param closure $controller the callback to run if matched
	 * @param boolean $overwrite True to overwrite a previous match
	 */
	public function map($method, $route, $controller, $overwrite = FALSE)
	{
		if($method != $this->method AND $method != '*')
		{
			return;
		}

		if( ! $overwrite AND $this->controller)
		{
			return;
		}

		$route = trim($route, '/');

		// Is this a regex? Regex must start with a tilde (~)
		if($route AND $route{0} === '~')
		{
			if(preg_match($route, $this->path, $matches))
			{
				$complete = array_shift($matches);

				// The following code tries to solve:
				// (Regex) "/^path/(\w+)/" + (Path) "path/word/other" = (Params) array(word, other)

				// Skip the regex match and continue from there
				$params = explode('/', trim(mb_substr($this->path, mb_strlen($complete)), '/'));

				if($params[0])
				{
					// Add captured group back into params
					foreach($matches as $match)
					{
						array_unshift($params, $match);
					}
				}
				else
				{
					$params = $matches;
				}

				$this->controller = $controller;
				$this->params = $params;
			}
		}
		elseif($route)
		{
			if(mb_substr($this->path, 0, mb_strlen($route)) === $route)
			{
				$this->controller = $controller;
				$this->params = explode('/', trim(mb_substr($this->path, mb_strlen($route)), '/'));
			}
		}
	}

	/**
	 * Invoke the controller and return the result. An empty result is a 404.
	 *
	 * @param string $path URL path of controller to invoke
	 */
	public function dispatch()
	{
		if($this->controller)
		{
			return call_user_func_array($this->controller, $this->params);
		}
	}
}

/**
 * Session class using encrypted cookies
 *
 * @todo We are sending duplicate cookie headers with this approach :(
 *
 * @see \Kit\Cookie
 */
class Session
{
	public $array;

	/**
	 * Create, save, and start a new session handler instance
	 *
	 * @param array $config
	 */
	public function __construct(array $config)
	{
		$this->config = $config;

		session_set_save_handler(
			array($this, 'justSmileAndWave'),
			array($this, 'justSmileAndWave'),
			array($this, 'read'),
			array($this, 'write'),
			array($this, 'justSmileAndWave'),
			array($this, 'justSmileAndWave')
		);

		// Set the session to be the same as the session data cookie we make
		// This allows us to overwrite it and only have one cookie.
		session_set_cookie_params( 
			$config['expires'],
			$config['path'], 
			$config['domain'], 
			$config['secure'], 
			$config['httponly'] 
		);

		// the following prevents unexpected effects when using objects as save handlers
		register_shutdown_function('session_write_close');

		// Start
		session_start();
	}

	/**
	 * We are *not* using a database, filesystem, or memcached instance requiring lots
	 * of setup, take-down, or cleanup. So, http://www.youtube.com/watch?v=DvYBZRwwGB4
	 */
	public function justSmileAndWave()
	{
		return true;
	}

	/**
	 * Fetch the session data from our cookie
	 *
	 * @param integer $id
	 * @return array
	 */
	public function read($id)
	{
		return Cookie::get($this->config['name'], $this->config);
	}

	/**
	 * Save the session data to the cookie
	 *
	 * @param integer $id
	 * @param array $data
	 * @return boolean
	 */
	public function write($id, $data)
	{
		return Cookie::set($this->config['name'], $data, $this->config);
	}
}

/**
 * SMTP client acting as a Mail Transfer Agent (MTA)
 */
class SMTP
{
	/**
	 * Hashcash is a computationally expensive operation for the sender, while being 
	 * easily verified by the receiver. It proves this email was worth working for 
	 * and isn't spam.
	 *
	 * @param string $email
	 * @return string
	 */
	public static function hashcash($email)
	{
		$count = 0;
		$hashcash = sprintf('1:20:%u:%s::%u', date('ymd'), $email, mt_rand());
		while (strncmp('00000', sha1($hashcash . $count), 5) !== 0) ++$count;
		return $hashcash . $count;
	}

	/**
	 * Compose a Content-Type string for the email DATA body
	 *
	 * @param string $body
	 * @param string $boundry
	 * @param string $type
	 * @return string
	 */
	public static function body($string, $boundary, $type='text/html')
	{
		return "--$boundary\r\n"
			. "Content-Type: $type; charset=utf-8\r\n"
			. "Content-Disposition: inline\r\n"
			. "Content-Transfer-Encoding: base64\r\n\r\n"
			. chunk_split(base64_encode($string));
	}

	/**
	 * Compose a valid SMTP DATA string from email message parts
	 *
	 * @param string $to
	 * @param string $subject
	 * @param string $html
	 * @param string $text
	 * @return string
	 */
	public static function message($to, $subject, $html, $text = NULL)
	{
		$boundary = uniqid();

		return 'Subject: =?UTF-8?B?' . base64_encode($subject) . "?=\r\n"
			. "To: $to\r\n"
			//. "Date: " . date('r') . "\r\n"
			. "MIME-Version: 1.0\r\n"
			. 'X-Hashcash: ' . self::hashcash($to) . "\r\n"
			. "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n"
			. "\r\n"
			. self::body($html, $boundary)
			. self::body($text ?: strip_tags($html), $boundary, 'text/plain')
			. "--$boundary--\r\n"
			. ".";
	}

	/**
	 * Mail an SMTP message to the recipient
	 *
	 * @param string $to
	 * @param string $from
	 * @param string $message
	 * @param string $user
	 * @param string $pass
	 * @param string $host
	 * @param string $port
	 * @return boolean
	 */
	public static function mail($to, $from, $message)
	{
		list(, $host) = explode('@', $to, 2);
		
		// MX records for email servers are optional :)
		if(getmxrr($host, $mx))
		{
			$host = current($mx);
		}

		if ($h = fsockopen($host, 25, $errno, $errstr))
		{
			$data = array(
				0,
				"EHLO $host",
				"MAIL FROM: <$from>",
				"RCPT TO: <$to>",
				'DATA',
				$message,
				'QUIT'
			);

			foreach($data as $c)
			{
				$c && fwrite($h, "$c\r\n");
				while(is_resource($h) && substr(fgets($h, 256), 3, 1) != ' '){}
			}

			return is_resource($h) && fclose($h);
		}
		else
		{
			return $errstr;
		}
	}
}

/**
 * Class to display associative arrays (such as database records) using closure callbacks for each column.
 */
class Table
{
	// Array of data rows
	public $rows;

	// List of all table columns
	public $columns;

	/**
	 * Create the table object using these rows
	 *
	 * @param array $rows to use
	 */
	public function __construct(array $rows)
	{
		$this->rows = $rows;
	}

	/**
	 * Add a new field to the validation object
	 *
	 * @param string $field name
	 */
	public function column($column, $name, $function = NULL, $sortable = TRUE)
	{
		$this->columns[$column] = array($name, $function, $sortable);
		return $this;
	}

	public function getColumns()
	{
		return array_keys($this->columns);
	}

	public function __invoke($column = NULL, $sort = 'desc', $params = array())
	{
		$html = "\n\t<thead>\n\t\t<tr>";

		foreach($this->columns as $key => $data)
		{
			$html .= "\n\t\t\t<th>";

			// If we allow sorting by this column
			if($data[2])
			{
				$direction = $sort == 'desc' ? 'asc' : 'desc';

				// Build URL parameters taking existing parameters into account
				$url = site_url(URL_PATH, array('column' => $key, 'sort' => $direction) + $params);

				$html .= '<a href="' . $url . '">' . $data[0] . '</a>';
			}
			else
			{
				$html .= $data['0'];
			}

			$html .= "</th>";
		}

		$html .= "\n\t\t</tr>\n\t</thead>\n\t<tbody>";

		$odd = 0;
		foreach($this->rows as $row)
		{
			$odd = 1 - $odd;

			$html .= "\n\t\t<tr class=\"". ($odd ? 'odd' : 'even') . '">';
			foreach($this->columns as $column => $data)
			{
				$html .= "\n\t\t\t<td>" . ($data[1] ? $data[1]($row) : $row[$column]) . "</td>";
			}

			$html .= "\n\t\t</tr>";
		}

		$html .= "\n\t</tbody>\n";

		return '<table>' . $html . "</table>\n";
	}
}

/**
 * Validator class based on anonymous functions.
 *
 * @see http://php.net/manual/en/functions.anonymous.php
 */
class Validator
{
	public $errors;

	/**
	 * Validate the given array of data using the functions set
	 *
	 * @param array $data to validate
	 * @return array
	 */
	public function __invoke(array $data)
	{
		$this->errors = array();
		foreach((array) $this as $key => $function)
		{
			if($key == 'errors') continue;

			$value = NULL;

			if(isset($data[$key]))
			{
				$value = $data[$key];
			}

			// If the callback is an array, it means the value is expected to be an array
			if(is_array($function))
			{
				$function = current($function);
				$value = (array) $value;

				foreach($value as $i => $element)
				{
					if($error = $function($element, $i, $value, $key, $this))
					{
						// There are to ways we can go with this...
						//$this->errors[$key] = $error;
						//break;

						// Better, but unexpected validation format
						$this->errors[$key][$i] = $error;
						unset($error);
					}
				}
			}
			else
			{
				$error = $function($value, $key, $this);
			}

			if($error)
			{
				$this->errors[$key] = $error;
			}
		}

		return ! $this->errors;
	}

	/**
	 * Return the validator errors
	 *
	 * @return array
	 */
	public function errors()
	{
		return $this->errors;
	}

	/**
	 * The value exists in the data as a string, matches the given regex, and
	 * is less than the max_length
	 *
	 * @param string $regex The regex to match the string
	 * @param integer $max_length The maximum lenght of the string
	 * @return boolean
	 */
	public static function string($value, $max, $min = 0)
	{
		if($value AND is_string($value) AND mb_strlen($value) < $max)
		{
			if( ! $min OR mb_strlen($value) > $min)
			{
				return TRUE;
			}
		}

		return FALSE;
	}
}

/**
 * Provide template inheritance to HTML, XML, or other text-based documents
 */
class View
{
	public $__blocks, $__append;
	public static $ext = '.php';

	/**
	 * Allows setting template values while still returning the object instance
	 * $view->title($title)->text($text);
	 *
	 * @return this
	 */
	public function __call($key, $args)
	{
		$this->$key = $args[0];
		return $this;
	}

	/**
	 * Set an array of template values
	 *
	 * @param array $values
	 * @return this
	 */
	public function set(array $values)
	{
		foreach($values as $key => $value)
		{
			$this->$key = $value;
		}

		return $this;
	}

	/**
	 * Render template HTML
	 *
	 * @param string $file the template file to load
	 * @return string
	 */
	public function __invoke($file, $dir = __DIR__)
	{
		extract((array) $this);
		ob_start();
		require rtrim($dir, '/') . '/' . $file . static::$ext;
		return trim(ob_get_clean());
	}

	/**
	 * Extend a parent template
	 *
	 * @param string $file name of template
	 */
	public function extend($file, $dir = __DIR__)
	{
		ob_end_clean(); // Ignore this child class and load the parent!
		ob_start();
		print $this($file, $dir);
	}

	/**
	 * Start a new block
	 */
	public function start()
	{
		ob_start();
	}

	/**
	 * Empty default block to be extended by child templates
	 *
	 * @param string $name of block
	 * @param string $default Default value to return if block is missing
	 * @return string
	 */
	public function block($name, $default = '')
	{
		if(isset($this->__blocks[$name]))
		{
			return $this->__blocks[$name];
		}

		return $default;
	}

	/**
	 * End a block
	 *
	 * @param string $name name of block
	 * @param boolean $keep_parent true to append parent block contents
	 */
	public function end($name, $keep_parent = FALSE)
	{
		$buffer = ob_get_clean();

		if( ! isset($this->__blocks[$name]))
		{
			$this->__blocks[$name] = $buffer;
			if($keep_parent) $this->__append[$name] = TRUE;
		}
		elseif(isset($this->__append[$name]))
		{
			if( ! $keep_parent) unset($this->__append[$name]);
			$this->__blocks[$name] = $buffer . $this->__blocks[$name];
		}
		else
		{
			$this->__blocks[$name] = $buffer;
		}

		print $this->__blocks[$name];
	}
}