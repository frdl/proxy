<?php 
namespace frdl\Proxy;
/*
* Patch if using frdl/remote-psr4
*/

class PatchAutoloadFunctions
{
  public function __construct(){
     $l=[];
     		 $l[]=!function_exists('\GuzzleHttp\Psr7\uri_for') && class_exists(\GuzzleHttp\Psr7\Functions::class) && \GuzzleHttp\Psr7\Functions::load;
         $l[]= !function_exists('\GuzzleHttp\Promise\promise_for') && class_exists(\GuzzleHttp\Promise\Functions::class) && \GuzzleHttp\Promise\Functions::load;
         $l[]= !function_exists('\GuzzleHttp\uri_template') && class_exists(\GuzzleHttp\Functions::class) && \GuzzleHttp\Functions::load;
     return $l;
  }
   
}
