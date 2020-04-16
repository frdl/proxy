<?php
namespace frdl\Proxy;

use Proxy\Proxy as BaseProxy;
use Proxy\Adapter\AdapterInterface;
use Proxy\Exception\UnexpectedValueException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Relay\RelayBuilder;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

class ClientProxy extends BaseProxy
{
	
    protected $toUri = null;
    public function __construct(AdapterInterface $adapter, $toUri = null)
    {
     //   call_user_func_array(parent::__construct, func_get_args());
	  parent::__construct($adapter, $toUri);
	   $this->toUri = $toUri;	
    }
			
	public function toUri(){
		if(null === $this->toUri){
			return $this->to( new Uri($_SERVER['REQUEST_URI']) . '');
		}
		return $this->to($this->toUri . '');
	}
	
    public function to($target)
    {
        if ($this->request === null) {
            throw new UnexpectedValueException('Missing request instance.');
        }
        $target = new Uri($target);
        // Overwrite target scheme and host.
        $uri = $this->request->getUri()
            ->withScheme($target->getScheme())
            ->withHost($target->getHost());
        // Check for custom port.
        if ($port = $target->getPort()) {
            $uri = $uri->withPort($port);
        }
        // Check for subdirectory.
      //   if ($path = $target->getPath()) {
      //       $uri = $uri->withPath(rtrim($path, '/') . '/' . ltrim($uri->getPath(), '/'));
      //   }
		 if ($path = $target->getPath()) {
           $uri = $uri->withPath(
			        //$uri->withPath(rtrim($path, '/') . 
			       '/' . trim($path, '/')			  
			   );
         }
		
        $request = $this->request->withUri($uri);
        $stack = $this->filters;
        $stack[] = function (RequestInterface $request, ResponseInterface $response, callable $next) {
            $response = $this->adapter->send($request);
	
            return $next($request, $response);
        };
        $relay = (new RelayBuilder)->newInstance($stack);
        return $relay($request, new Response);
    }	
	
	
}
