<?php 
namespace frdl\Proxy;

use Proxy\Proxy as Proxy;
use Proxy\Adapter\Guzzle\GuzzleAdapter as GuzzleAdapter;
use Proxy\Filter\RewriteLocationFilter as RewriteLocationFilter;
use Proxy\Filter\RemoveEncodingFilter as RemoveEncodingFilter;
use Zend\Diactoros\ServerRequestFactory as ServerRequestFactory;
use GuzzleHttp\Client as Client;

use webfan\hps\patch\Uri as Uri;
use webfan\hps\patch\Request as Request;

use function webfan\hps\patch\originHeaders;
use function webfan\hps\patch\lastModified;


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
	
	public function __construct(string $deploy = null, string $targetLocation = null, string $targetSeverHost = null, string $httpHost = null, string $method = null, $protocol = null){
		
		   (new \frdl\webfan\App\LoadSomeCoreFunctions());
           (new \GuzzleHttp\LoadGuzzleFunctionsForFrdl());
		
		$this->targetSeverHost = $targetSeverHost ? $targetSeverHost : $_SERVER['SERVER_NAME'];
		$this->httpHost = $httpHost ? $httpHost : $_SERVER['HTTP_HOST'];
		$this->protocol = $protocol ? $protocol : ((\frdl\webfan\App::God(false)->is_ssl()) ? 'https' : 'http');
		$this->targetLocation = $targetLocation ? $targetLocation : $_SERVER['REQUEST_URI'];
		$this->method = $method ? $method : $_SERVER['REQUEST_METHOD'];	
		$this->deploy = $deploy;
		
		$_SERVER['SERVER_ADDR'] = (isset($_SERVER['SERVER_ADDR'])) ? $_SERVER['SERVER_ADDR'] : \gethostbyname( $_SERVER['SERVER_NAME'] );
		$_SERVER['SERVER_NAME'] = (isset($_SERVER['SERVER_NAME'])) ? $_SERVER['SERVER_NAME'] : $_SERVER['HTTP_HOST'];
		
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
		                                [
									//	 'allow_redirects' => ['track_redirects' => true],
										 'allow_redirects' => false,
										 'http_errors' => false
										],
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
		$headers= $headers?: \frdl\webfan\App::God(false)->{'parseHeaders'}($server);
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
		
		
		$uri = (is_string($url)) ? new Uri($url) :new Uri( \frdl\webfan\App::God(false)->unparse_url($p) ) ;
	

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
			 
			 ->withHeader(self::HEADER_HOST_IMPERSONATION, $host)
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
		
		if(null===$reverse_host){
	      $reverse_host = $_SERVER['HTTP_HOST'];	
		}
				
		if(null===$serverVars){
		  $serverVars = $_SERVER;	
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
												\frdl\webfan\App::God(false)->{'parseHeaders'}($serverVars)/* $headers*/,
												$_COOKIE, $_FILES, $serverVars//,
												//'php://input'
												//$_POST
												//stream_get_contents('php://input')
												//rawurlencode($_POST)
											   );
		
         $guzzle = new Client(array_merge([
		//	 'allow_redirects' => ['track_redirects' => true], 
			 'http_errors' => false
		 ], $config));
         $adapter = new GuzzleAdapter($guzzle);	
         $proxy = new \webfan\hps\Client\Proxy($adapter, $request->getUri());


		
		
		 $cstr = '';
						  foreach($_COOKIE as $name => $value){
						
							  $cstr.= "$name=$value;";
							  
							
						  }
		                   if(0<strlen($cstr)){
							     $request = $request->withHeader('Cookie', trim($cstr, '; '), true );  
						   }
			
				
			
			 $forIp = ((isset($_SERVER['HTTP_X_FORWARDED_FOR'])) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR']);
			 $request = $request->withHeader(self::HEADER_IP_IMPERSONATION, $forIp);
		
	         $request = $request->withHeader(self::HEADER_HOST_IMPERSONATION, $host);
			 $request = $request->withHeader('X-Frdlweb-Proxy',  $_SERVER['SERVER_ADDR']);		
		
     return $proxy
		 	 ->forward($request)
    	 
    	 ->filter(new RemoveEncodingFilter())
		 
	    ->filter(function ($request, $response, $next) use($host, $ClassResponse, $method) {

			
		      
			 $request = $request->withHeader(self::HEADER_HOST_IMPERSONATION, $host);
			 $request = $request->withHeader('X-Frdlweb-Proxy', $_SERVER['SERVER_ADDR']);			

			

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
	
	 
	
	
