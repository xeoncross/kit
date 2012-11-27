<?php
class RouterTest extends PHPUnit_Framework_TestCase
{
	public function testSimpleMap()
	{
		$router = new \Kit\Router('GET', 'foo/bar');

		$router->map('GET', 'foo', function()
		{
			return TRUE;
		});

		$this->assertTrue($router->dispatch());
	}

	public function testBadMap()
	{
		$router = new \Kit\Router('POST', 'foo/bar');

		$router->map('GET', 'foo', function()
		{
			return TRUE;
		});

		$this->assertNull($router->dispatch());
	}

	public function testOverwriteMap()
	{
		$router = new \Kit\Router('GET', 'foo/bar');

		$router->map('GET', 'foo', function()
		{
			return FALSE;
		});

		$router->map('GET', 'foo', function()
		{
			return FALSE;
		});

		$router->map('GET', 'foo', function()
		{
			return TRUE;
		}, TRUE);

		$this->assertTrue($router->dispatch());
	}

	public function testParamMap()
	{
		$router = new \Kit\Router('GET', 'bar/foo/baz');

		$router->map('GET', 'bar', function($foo, $baz)
		{
			return $foo . $baz;
		});

		$this->assertTrue($router->dispatch() === 'foobaz');
	}

	public function testRegexMap()
	{
		$router = new \Kit\Router('GET', 'bar/foo');

		$router->map('GET', '~(.+?)/foo~', function()
		{
			return TRUE;
		});

		$this->assertTrue($router->dispatch() === TRUE);

	}

	public function testRegexMapWithParams()
	{
		$router = new \Kit\Router('GET', 'bar/foo/baz');

		$router->map('GET', '~(.+?)/foo~', function($bar, $baz)
		{
			return $bar . $baz;
		});

		$this->assertTrue($router->dispatch() === 'barbaz');
	}
}

