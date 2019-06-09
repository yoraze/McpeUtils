# McpeQuery
A class in PHP that retrieves Query information from almost any MinecraftPE server. What else is there to tell?

# Example

``` php
<?php

//Server IP address
$ip = "0.0.0.0";
//Server port
$port = 19132;

//Timeout
$timeout = 5;



$query = new \mcpe\Query($ip, $port, $timeout);

//Query info(array)
$info = $query->getInfo();

?>
```
