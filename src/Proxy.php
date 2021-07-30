<?php 

namespace frdl\Proxy;

use Proxy\Adapter\Guzzle\GuzzleAdapter as GuzzleAdapter;
use Proxy\Filter\RewriteLocationFilter as RewriteLocationFilter;
use Proxy\Filter\RemoveEncodingFilter as RemoveEncodingFilter;
use Zend\Diactoros\ServerRequestFactory as ServerRequestFactory;
use GuzzleHttp\Client as Client;

use webfan\hps\patch\Uri as Uri;
use webfan\hps\patch\Request as Request;

use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\Handler\Proxy as ProxyHandler;
use GuzzleHttp\Handler\StreamHandler;

use GuzzleHttp\HandlerStack;
use Kevinrob\GuzzleCache\CacheMiddleware;
use League\Flysystem\Adapter\Local;
use Kevinrob\GuzzleCache\Strategy\PrivateCacheStrategy;
use Kevinrob\GuzzleCache\Storage\FlysystemStorage;
use League\Flysystem\Local\LocalFilesystemAdapter;
use Kevinrob\GuzzleCache\KeyValueHttpHeader;
use Kevinrob\GuzzleCache\Strategy\GreedyCacheStrategy;

use Kevinrob\GuzzleCache\Storage\DoctrineCacheStorage;
use Doctrine\Common\Cache\FilesystemCache;

class Proxy
{
	
	const HEADER_DEPLOY_NEGOTIATION = 'X-Frdlweb-Negotiation-Stage';
	const HEADER_HOST_NEGOTIATION = 'X-Frdlweb-Negotiation-Host';
	const HEADER_HOST_IMPERSONATION = 'X-Frdlweb-Proxy-For-Host';
	const HEADER_IP_IMPERSONATION = 'X-Forwarded-For';
	
	
	protected $targetSeverHost;
	protected $httpHost;
	protected $targetLocation;
	protected $method;
	protected $protocol;
	protected $deploy;		
	protected $HostHeaderOverwrite = false;
	protected $fakeHeader;
	protected $_callStack = [];
	protected $_config=[];
	protected $_handler;
	
	public function __call($name, $params){
	    $ix = count($this->_callStack);
	    $_method=explode('$', $name);
	    $method = $_method[0];
	    $when = 'createServerRequest';
	    if(count($_method)>1 && isset($_method[1])){
		if(is_numeric($_method[1])){
		  $ix = intval($_method[1]);	
		}else{
		    $when = $_method[1];
		}
	    }else{
		$when = 'createServerRequest';    
	    }
	    while(isset($this->_callStack[$ix])){
		$ix++;    
	    }
	    $this->_callStack[$ix]=[$when, $method,$params];	
            return $this;
        }
	
	
	public function __construct(string $deploy = null, string $targetLocation = null, string $targetSeverHost = null, string $httpHost = null, string $method = null, $protocol = null, bool $HostHeaderOverwrite = null){

		$l = new PatchAutoloadFunctions();
		
		
     		$this->targetSeverHost = $targetSeverHost ? $targetSeverHost : $_SERVER['SERVER_NAME'];
		$this->httpHost = $httpHost ? $httpHost : $_SERVER['HTTP_HOST'];
		$this->protocol = $protocol ? $protocol : (($this->is_ssl()) ? 'https' : 'http');
		$this->targetLocation = $targetLocation ? $targetLocation : $_SERVER['REQUEST_URI'];
		$this->method = $method ? $method : $_SERVER['REQUEST_METHOD'];	
		$this->deploy = $deploy;
		$this->HostHeaderOverwrite = $HostHeaderOverwrite ? $HostHeaderOverwrite : false;
		$this->fakeHeader = self::HEADER_HOST_IMPERSONATION;
		$_SERVER['SERVER_ADDR'] = (isset($_SERVER['SERVER_ADDR'])) ? $_SERVER['SERVER_ADDR'] : \gethostbyname( $_SERVER['SERVER_NAME'] );
		$_SERVER['SERVER_NAME'] = (isset($_SERVER['SERVER_NAME'])) ? $_SERVER['SERVER_NAME'] : $_SERVER['HTTP_HOST'];
		
		$this->_handler=$this->choose_handler();
		
		$this->_config = [								
							//	 'allow_redirects' => ['track_redirects' => true],									
							'allow_redirects' => false,									
							'http_errors' => false,									
							//'handler' => $this->choose_handler(),									
							'headers' => [											
								'user-agent' => __CLASS__,	
								'accept-encoding'=>'deflate, gzip',
							],									
						];
	}

public function withCacheMiddleware(CacheMiddleware $CacheMiddleware){	
   $stack = HandlerStack::create();	
   $stack->push($CacheMiddleware);
   $stack->push($this->_handler);	
   $this->_handler = $stack;	
  return $this;
}
	
	
public function withCacheDir(string $dir = null, int $ttl= 1800, bool $force=true){
	
	if(null === $dir){
	   $dir =   \sys_get_temp_dir().\DIRECTORY_SEPARATOR.sha1(__FILE__);	
	}
	if(true === $force && !is_dir($dir)){
	   mkdir($dir, 0755, true);	
	}
	
	$stack = HandlerStack::create();
	
$stack->push(
  new CacheMiddleware(
    new GreedyCacheStrategy(
      new DoctrineCacheStorage(
        new FilesystemCache($dir)
      ),
      $ttl, // the TTL in seconds
      new KeyValueHttpHeader([
	      'Authorization', 
	      'Host',
	      'Origin', 
	      'Cookie', 
	      'Cache-Control', 
	      'X-Frdl-Content-Negotiation',
	      'X-Frdlweb-Content-Negotiation',
	      'X-Webfan-Content-Negotiation',
      ]) 
    )
  ),
  'greedy-cache'
);

// $stack->push($this->_handler);
	
  $this->_handler = $stack;
	
  return $this;
}
	
public function withConfig(array $config){
	$this->_config=array_merge($this->_config, $config);
  return $this;
}
	
public function withConfigValue(string $key, $value){
	$this->_config[$key] = $value;
  return $this;
}
	
protected function choose_handler()
{
    $handler = null;
    if (function_exists('curl_multi_exec') && function_exists('curl_exec')) {
        $handler = ProxyHandler::wrapSync(new CurlMultiHandler(), new CurlHandler());
    } elseif (function_exists('curl_exec')) {
        $handler = new CurlHandler();
    } elseif (function_exists('curl_multi_exec')) {
        $handler = new CurlMultiHandler();
    }

    if (ini_get('allow_url_fopen')) {
        $handler = $handler
            ? ProxyHandler::wrapStreaming($handler, new StreamHandler())
            : new StreamHandler();
    } elseif (!$handler) {
        throw new \RuntimeException('GuzzleHttp requires cURL, the '
            . 'allow_url_fopen ini setting, or a custom HTTP handler.');
    }

    return $handler;
}
	
	
  public function withFakeHost(?bool $withFakeHost = null){
	if(null===$withFakeHost){
	   $withFakeHost = true;	
	}
	  
	$this->HostHeaderOverwrite = !$withFakeHost;  
	  
    return $this;
  }
	

  public function withFakeHeader(?string $withFakeHeader = null){
	if(null===$withFakeHeader){
	   return $this->withFakeHost(true);	
	}
	  
	$this->fakeHeader = $withFakeHeader;  
	  
    return $this;
  }	
	
  public function is_ssl() {
    if ( isset($_SERVER) && isset($_SERVER['HTTPS']) ) {
        if ( 'on' == strtolower($_SERVER['HTTPS']) )
            return true;
        if ( '1' == $_SERVER['HTTPS'] )
            return true;
    } elseif (isset($_SERVER) && isset($_SERVER['SERVER_PORT']) && ( '443' == $_SERVER['SERVER_PORT'] ) ) {
        return true;
    }
     return false;	
   }	
	
	public function bounce(){
		return isset($_SERVER['HTTP_X_FRDLWEB_PROXY']) 
		     &&  $_SERVER['HTTP_X_FRDLWEB_PROXY'] === $_SERVER['SERVER_ADDR']
		     && ($this->targetSeverHost === $this->httpHost || $this->targetSeverHost === $_SERVER['SERVER_NAME'])
		     && $this->targetLocation === $_SERVER['REQUEST_URI'];
	}
	
	
	protected function send(&$response){
		$response->send(true); 
	}
	
	public function handle(bool $verbose = true){
		$response = false;
	 
		
	 if(!$this->bounce()){	
		$response =  $this->createProxy(
	                                 $this->targetSeverHost,
		                             $this->protocol,
		                             $this->targetLocation,
		                             $this->httpHost,
		                             $this->method,
		                             $this->_config,
	                                    $_SERVER
	                                   /*$reverse_host = null,
		                                 $reverse_protocol = null,
										 $reverse_uri = null,
										 $host = null,
										 $method = null,
		                                 array $config = ['http_errors' => true],
							             $serverVars = null,
							             $ClassResponse = null
										 */)->toUri();

	
	        $headersRedirect = $response->getHeader(\GuzzleHttp\RedirectMiddleware::HISTORY_HEADER);
		    if($headersRedirect){
			 	$response = $response->withHeader('Location', $headersRedirect[0]);
			 }
		
		if(true===$verbose){
		 $this->send($response);
		}
	 }
		
		
	  return $response;	
	}
	
	public function parseHeaders($serverVars = null, &$ifNoneMatch = null, &$ifModifiedSince=null){
if( !is_array($serverVars))$serverVars = $_SERVER;

$headers = array();
foreach($_SERVER as $key=>$value)
{
                if (substr($key,0,5)=="HTTP_") {
                     $key=str_replace(" ","-",ucwords(strtolower(str_replace("_"," ",substr($key,5)))));
                     $headers[$key]=$value;
                     if( $key == 'If-None-Match' )
                      {
                        $ifNoneMatch = $headers['If-None-Match'];
                        if(substr($ifNoneMatch, 0, 1) !== '"')$ifNoneMatch = null;
                      }
                     if( $key == 'If-Modified-Since' )
                      {
                        $ifModifiedSince = $headers['If-Modified-Since'];
                      }
                }
}
return $headers;
}
	
	
	
	public function unparse_url($parsed_url) {
  $scheme   = isset($parsed_url['scheme']) ? $parsed_url['scheme'] . '://' : '';
  $host     = isset($parsed_url['host']) ? $parsed_url['host'] : '';
  $port     = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
  $user     = isset($parsed_url['user']) ? $parsed_url['user'] : '';
  $pass     = isset($parsed_url['pass']) ? ':' . $parsed_url['pass']  : '';
  $pass     = ($user || $pass) ? "$pass@" : '';
  $path     = isset($parsed_url['path']) ? $parsed_url['path'] : '';
  $query    = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : '';
  $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : '';
  return "$scheme$user$pass$host$port$path$query$fragment";	
}
	
	protected function createServerRequest(
		
		    $host = null,
		    $url = null,//marshalUriFromSapi($server, $headers),
		    $method = null, //marshalMethodFromSapi($server),
            $query=  null,//null	
		
            $headers= null, //null
            $cookies= null,//null	
		
		    $files = null,		
		    $server = null,                  
        
            $body = null, //'php://input',

           // marshalProtocolVersionFromSapi($server)
		    $protocol = '1.1',
	        $parsedBody =null){
		
		
		//if(!defined('\MX_SESSION_NAME'))define('MX_SESSION_NAME', 'PHPSESSID');
		
		
		$server = $server?:$_SERVER;
		$files = $files?:$_FILES;
		$cookies = $cookies?:$_COOKIE;
		$query = $query?:$_GET;
		$method = $method?:$server['REQUEST_METHOD'];
		$headers= $headers?: $this->{'parseHeaders'}($server);
		//if (null === $cookies && null!==$headers && array_key_exists('cookie', $headers)) {
         //   $cookies = parseCookieHeader($headers['cookie']);
      //  }
		$body = $body?:'php://input';
		
		$p = parse_url($url);	
        if(isset($p['query'])){
			parse_str($p['query'], $queryParams);
		}else{
			$queryParams = [];
		}
		
	 	$p['path'] = '/'.ltrim($p['path'], '/');
		
		
		$queryParams = array_merge($query, $queryParams);
		
		$query = \http_build_query($queryParams);
		
		if(null === $host ){
		  $host = $p['host'];	
		}		
		
		
		$uri = (is_string($url)) ? new Uri($url) :new Uri( $this->unparse_url($p) ) ;
	

		$uri->withQuery($query);
		$uri->withPath($p['path']);	
      //  $uri->withHost($host);	
		$uri->withHost($p['host']);	
        if(isset($p['port']))$uri->withPort($p['port']);		
        $uri->withScheme($p['scheme']);	
		
        $forIp = ((isset($server['HTTP_X_FORWARDED_FOR'])) ? $server['HTTP_X_FORWARDED_FOR'] : $server['REMOTE_ADDR']);
		//Request($uri = null, string $method = null, $body = 'php://temp', array $headers = [])
		
		$input = file_get_contents('php://input');
		
	//	print_r($method);
		 parse_str($input, $parsedBody);	
		 $json = json_decode($input);
	//	 print_r($parsedBody);	
		
	  $stream = new \Zend\Diactoros\Stream('php://memory', 'wb+');		
		
   if('POST' === $method || 'PUT' === $method){
	  
	   if( is_array((array)$json) ){			    
		  $stream->write($input);
	 }elseif( is_array($parsedBody) ){		    
		 // $stream->write(http_build_query($_POST));
	     $stream->write($input);
	 }else{
		     $stream->write($input);
	   }
  }			
		
		
		 $REQUEST = (new Request(
			 $uri,
			 $method,
		     $stream,
			 $headers
		 ))
			 
			 ->withHeader($this->fakeHeader, $host)
			 ->withHeader(self::HEADER_IP_IMPERSONATION, $forIp)
			  ->withMethod($method)	
			  ->withBody($stream)
			 ;

		foreach($headers as $k => $v){
			 $REQUEST = $REQUEST ->withHeader($k, $v);
		}
		
		

		
		//multipart/form-data
	
		if('POST' === $method || 'PUT' === $method){			
			 if( 0<count($_FILES) ){
				$REQUEST = $REQUEST ->withHeader('Content-type', 'multipart/form-data');
			 }elseif( null!== $json && (is_array($json) ||is_object($json))){			    
		        $REQUEST = $REQUEST ->withHeader('Content-type', 'application/json');
	         }elseif( is_array($parsedBody) ){
				$REQUEST = $REQUEST ->withHeader('Content-type', 'application/x-www-form-urlencoded');
			 }else{
			 	 $REQUEST = $REQUEST ->withHeader('Content-type', 'application/x-www-form-urlencoded');
			 }
		}
		
		
		
		if($this->deploy){
		  $REQUEST = $REQUEST ->withHeader(self::HEADER_DEPLOY_NEGOTIATION, $this->deploy);			
		}
		
		
		foreach($this->_callStack as $_call){
		    if(__FUNCTION__!== $_call[0]){
			continue;    
		    }
		    $REQUEST = call_user_func_array([$REQUEST, $_call[1]], $_call[2]);
		}
		
		return $REQUEST;
	}
	
	protected function createProxy(        
										 $reverse_host = null,
		                                 $reverse_protocol = null,
										 $reverse_uri = null,
										 $host = null,
										 $method = null,
		                                 array $config = ['http_errors' => false],
							             $serverVars = null,
							             $ClassResponse = null){
				
		if(null===$serverVars){
		  $serverVars = $_SERVER;	
		}
		if(null===$reverse_host){
	      $reverse_host = $serverVars['HTTP_HOST'];	
		}
					
		if(null===$ClassResponse){
		  $ClassResponse ='\\'.trim(__NAMESPACE__, '\\ ').'\\'.'Response';	
		}			
		if(null===$reverse_protocol){
		  $reverse_protocol = 'https';	
		}
		
		if(null===$reverse_uri){
		  $reverse_uri = $serverVars['REQUEST_URI'];	
		}		
		
		
		
		if(null===$host){
		  $host = (!isset($serverVars['SERVER_NAME']) || $serverVars['SERVER_NAME'] !==$serverVars['HTTP_HOST']) ? $serverVars['HTTP_HOST'] : $reverse_host;	
		}
		if(null===$method){
		  $method = $serverVars['REQUEST_METHOD'];
		}	
		
	
		 $url = rtrim($reverse_protocol, ':// ').'://'.$reverse_host.''.$reverse_uri;	

		 $request =	$this-> createServerRequest( $host, $url, $method, $_GET/*$query$Params*/, 
												$this->{'parseHeaders'}($serverVars)/* $headers*/,
												$_COOKIE, $_FILES, $serverVars//,
												//'php://input'
												//$_POST
												//stream_get_contents('php://input')
												//rawurlencode($_POST)
											   );
		
         $guzzle = new Client(array_merge([
		//	 'allow_redirects' => ['track_redirects' => true], 
			 'http_errors' => false,
		        // 'handler' => $this->choose_handler(),
		 ], array_merge($config,
			    [
			      'handler'=>$this->_handler
			    ]   
		)));
	 	
         $adapter = new GuzzleAdapter($guzzle);	
        // $proxy = new \webfan\hps\Client\Proxy($adapter, $request->getUri());
           $proxy = new ClientProxy($adapter, $request->getUri());

		foreach($this->_callStack as $_call){
		    if('Client' !==  $_call[0]){
			continue;    
		    }
		    $proxy = call_user_func_array([$proxy, $_call[1]], $_call[2]);
		}
		
		 $cstr = '';
						  foreach($_COOKIE as $name => $value){
						
							  $cstr.= "$name=$value;";
							  
							
						  }
		                   if(0<strlen($cstr)){
							     $request = $request->withHeader('Cookie', trim($cstr, '; '), true );  
						   }
			
				
			
			 $forIp = ((isset($serverVars['HTTP_X_FORWARDED_FOR'])) ? $serverVars['HTTP_X_FORWARDED_FOR'] : $serverVars['REMOTE_ADDR']);
			 $request = $request->withHeader(self::HEADER_IP_IMPERSONATION, $forIp);
		
	         $request = $request->withHeader($this->fakeHeader, $host);
			 $request = $request->withHeader('X-Frdlweb-Proxy',  $serverVars['SERVER_ADDR']);		
		
	       foreach($this->_callStack as $_call){
		    if(__FUNCTION__!== $_call[0]){
			continue;    
		    }
		    $request = call_user_func_array([$request, $_call[1]], $_call[2]);
		}
		
     return $proxy
		 	 ->forward($request)
    	 
    	 ->filter(new RemoveEncodingFilter())
		 
	    ->filter(function ($request, $response, $next) use($host, $ClassResponse, $method, $serverVars) {

			
		      
			 $request = $request->withHeader($this->fakeHeader, $host);
			 $request = $request->withHeader('X-Frdlweb-Proxy', $serverVars['SERVER_ADDR']);	
			 $request = $request->withHeader('X-Forwarded-For', $serverVars['REMOTE_ADDR']);			

						
		    if(true===$this->HostHeaderOverwrite){			
			    $request = $request->withHeader('Host', $host);			
		    }
		    

	$response = $next($request, $response);
    $MyResponse = new $ClassResponse($response);
			
			
			
 foreach($MyResponse->getHeaders() as $n => $_v){


	 
 foreach($_v as $v){	 

	 
	     if('Location'===$n){

		 }elseif('Set-Cookie' === $n){					
			 
					 $RequestCookies = [];
					 
					 if(!is_array($v)){
						 $v = [$v];
					 }
				     foreach( $v as $i => $hv){ 
					   $CookieObject = ( function_exists('\http_parse_cookie')) 
					    ? \http_parse_cookie( trim($hv), 0 ) 
					    : new \webfan\hps\Parse\Cookie(trim($hv), 0 );
					     $cookies = $CookieObject->cookies;
					
				      	foreach($cookies as $cookieName => $cookieValue){
						   $RequestCookies[$cookieName] = [
							'expires' => $CookieObject->expires,
							'value' => $cookieValue,
							'domain' => $CookieObject->domain,
							'path' => $CookieObject->path,
							'secure' => (bool)$CookieObject->secure,
						 ];
						
						
					  }					   
				    }	 
					 
			 
			 			
			 
			 
						  foreach($RequestCookies as $name => $Cookie){
							 //  print_r($name);  
							  $time = time() + 2 * 60 * 60;
							  extract($Cookie);
							  $cs = "$name=$value; expires=$expires; domain=$domain; path=$path; $secure";
							  $MyResponse = $MyResponse->withHeader('Set-Cookie', $cs);
							 			
							//  if($name===\MX_SESSION_NAME && strlen(trim($value)) && 'sess' === substr($value, 0, strlen('sess'))){
									// session_id(urldecode($value));
   						  //    }
							  
			
		
						  }
			
			 
   }else{
			$MyResponse = $MyResponse->withHeader($n, $v, true ); 
		 }
 
 }//foreach
 }//foreach   

										 

		 $MyResponse = $MyResponse->withHeader('X-Powered-By', 'Webfan Homepagesystem', false );
			
		 return $MyResponse;
 })
		
//	->filter(new RewriteLocationFilter())
		 
	  ;		
	}
	
}
