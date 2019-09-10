<?php

namespace mcpe;

class Query{
    /** @var string */
    protected $ip;
    /** @var int */
    protected $port;
    /** @var int */
    protected $timeout;

    /** @var resource */
    protected $socket = null;

    public function __construct(string $ip, int $port, int $timeout = 1){
        $this->ip = $ip;
        $this->port = $port;
        $this->timeout = $timeout;
    }

    public function connect() : void{
        $this->resolveSRV();
        $this->socket = stream_socket_client("udp://" . $this->ip . ":" . $this->port, $errno, $errstr, $this->timeout);
        if($errno || $this->socket === false){
            throw new \RuntimeException("Socket connection error");
        }

        stream_set_timeout($this->socket, $this->timeout);
        stream_set_blocking($this->socket, true);
    }

    public function close() : void{
        fclose($this->socket);
    }

    public function getInfo() : \stdClass{
        $data = new \stdClass;

        $data->query = $this->getQueryInfo();
        $data->ping = $this->getPingInfo();

        return $data;
    }

    public function getQueryInfo() : ?\stdClass{
        $packet = $this->writePacket(9);

        if($packet === false){
            throw new \RuntimeException("Challenge packet error");
        }

        $packet = $this->writePacket(0, pack("N", $packet["payload"]) . pack("c*", 0x00, 0x00, 0x00, 0x00));

        $query = new \stdClass;

        if($packet == false){
            $query->error = "Statistic packet error";
            return $query;
        }

        $data = substr($packet["payload"], 11); // splitnum + 2 int
        $data = explode("\x00\x00\x01player_\x00\x00", $data);

        if(count($data) !== 2){
            $query->error = "Data error";
            return $query;
        }

        $status["players"] = explode("\x00", substr($data[1], 0, -2));
        $data = explode("\x00", $data[0]);
        $last = false;
        foreach($data as $val){
            if($last === false){
                $last = $val;
            }else{
                $query->{$last} = $val;
                $last = false;
            }
        }

        // Parse "plugins", if any
        if($query->plugins !== ""){
            $plugins = explode(": ", $query->plugins, 2);

            $query->raw_plugins = $plugins;
            $query->software = $plugins[0];

            if(count($plugins) === 2){
                $query->plugins = explode("; ", $plugins[1]);
            }
        }else{
            $query->software = "Vanilla";
        }

        return $query;
    }

    public function getPingInfo() : ?\stdClass{
        $pingPacket = "\x01" . "\x00\x00\x00\x00\x00\x00\x00\x00" . "\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78";
        //packetId + long(0) + magic

        fwrite($this->socket, $pingPacket);
        $packet = fread($this->socket, 65535);

        if(!$packet){
            return null;
        }

        $result = new \stdClass;
        $data = explode(";", substr($packet, 1 + 8 + 8 + 16 + 2));
        foreach($data as $offset => $value){
            switch($offset){
                case 0:
                    $result->game_id = $value;
                    break;
                case 1:
                    $result->hostname = $value;
                    break;
                case 2:
                    $result->protocol = $value;
                    break;
                case 3:
                    $result->version = $value;
                    break;
                case 4:
                    $result->numplayers = $value;
                    break;
                case 5:
                    $result->maxplayers = $value;
                    break;
                case 6:
                    $result->serverid = $value;
                    break;
                case 7:
                    $result->software = $value;
                    break;
                case 8:
                    $result->gametype = $value;
                    break;
            }
        }

        return $result;
    }

    public function resolveSRV() : void{
        $address = &$this->ip;

        if(ip2long($address) !== false){
            return;
        }

        $record = dns_get_record("_minecraft._tcp.$address", DNS_SRV);
        if(empty($record)){
            return;
        }

        if(isset($record[0]["target"])){
            $address = $record[0]["target"];
        }
    }

    public function writePacket(string $command, string $append = "") : ?array{
        $command = "\xFE\xFD" . chr($command) . pack("c*", 0x01, 0x02, 0x03, 0x04) . $append;

        fwrite($this->socket, $command);

        $data = fread($this->socket, 65535);
        if(!$data){
            return null;
        }

        if(strlen($data) < 5 || $data[0] !== $command[2]){
            return null;
        }

        return $this->readPacket($data);
    }

    public function readPacket(string $buffer) : array{
        $redata = [];
        $redata["packetType"] = ord($buffer[0]);
        $redata["sessionID"] = unpack("N", substr($buffer, 1, 4))[1];
        $redata["payload"] = substr($buffer, 5);

        return $redata;
    }
}