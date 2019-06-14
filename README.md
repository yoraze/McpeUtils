# McpeUtils


## Query example

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

## Rcon example
``` php
<?php
$rcon = new MCRcon("127.0.0.1", 19132);

$rcon->connect();
$rcon->authorize("mytoppassword");

echo $rcon->sendCommand("help");

```
