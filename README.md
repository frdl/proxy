# frdl/proxy
Simple Php Proxy based on Guzzle.

## Installation
Use Composer...
````
composer require frdl/proxy
````
...or the [Webfan Installer](https://frdl.webfan.de/install/php/) if you would like to build a larger project.

## Usage

````php
<?php
use frdl\Proxy\Proxy;

 require 'vendor/autoload.php'; 
 
 	$proxy = (new Proxy(null,
                      $_SERVER['REQUEST_URI'],
                      'green.example.com',  //target host
                      $_SERVER['HTTP_HOST'],  //User Input, forward optionaly*
                      $_SERVER['REQUEST_METHOD'], 
                      'https', 
                      false))
        ->withFakeHost(true) //*Do overwrite/not use users host header
        //...or...
        ->withFakeHeader('X-Forwarded-Host')
    ;
    
	$proxy->handle(true);
````

Internally the proxy ignores the `bounce`-detection silently to fallback to any localhost scripts.
You can use it before/without handling the HTTP-Forwarding, e.g. to perform a (test-)request on the same host.
````php
if(!$proxy->bounce()){	
 	$proxy = (new Proxy(null,
                      $_SERVER['REQUEST_URI'],
                      'blue.example.com',  //target host
                      'example.com',  //set the host header on the target script
                      $_SERVER['REQUEST_METHOD'], 
                      'https', 
                      true))
  ->handle(true);                    
}
````

