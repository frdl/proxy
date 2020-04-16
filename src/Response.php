<?php 
	
namespace Webfan\App;


class TestResponse	
{
	protected $_response;
	public function __construct(\Psr\Http\Message\ResponseInterface $response){
		$this->_response = $response;
	}	
	public function __call($name, $params){
		if(!is_callable([$this->_response, $name])){
		   throw new \Exception(get_class($this->_response ).'->'.$name.' is not callable in '.__METHOD__);	
		}
		
		$r = call_user_func_array([$this->_response, $name], $params);
		if($r instanceof $this){
		   return $r;	
		}elseif(is_object($r) && in_array(\Psr\Http\Message\ResponseInterface::class, class_implements($r))){
		   return new self($r);	
		}else{
		   return $r;	
		}
	}
	
	public function send($verbose = true){
		

		
		if(is_callable([$this->_response, 'send'])){
		   return $this->_response->send($verbose);	
		}		
		
		 if(true !== $verbose){	
			return $this->_response->getBody();
	     }	

		 return (new \Zend\Diactoros\Response\SapiStreamEmitter)->emit($this->_response);
	}	
}


 
	
	
