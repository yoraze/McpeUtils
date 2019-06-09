<?php

namespace mcpe;

class Query {
    public $ip, $port, $timeout;
    public function __construct($ip, $port, $timeout = 1){
        $this->ip = $ip;
        $this->port = $port;
        $this->timeout = $timeout;
    }
    public function getInfo(){
        $data = [
            "status" => false,
            "error" => "",
            "isset_query" => false,
            "isset_ping" =>  false
        ];
        $this->resolveSRV();
        $socket = stream_socket_client("udp://".$this->ip.":".$this->port, $errno, $errstr, $this->timeout);
        if($errno || $socket === false){
            $data["error"] = "Socket connection error";
            return $data;
        }
        stream_set_timeout($socket, $this->timeout);
        stream_set_blocking($socket, true);
        if($this->getQueryStatus($socket, $data) or $this->getPingStatus($socket, $data)){
            if(!$data["isset_ping"]){
                $this->getPingStatus($socket, $data);
            }
            $data["status"] = true;
        }
        fclose($socket);
        return $data;
    }
    public function getQueryStatus($socket, &$status){
        $packet = $this->writePacket($socket, 9);
        if($packet == false){
            $status["error"] = "Challenge packet error";
            return false;
        }
        $packet = $this->writePacket($socket, 0, pack("N", $packet["payload"]).pack("c*", 0x00, 0x00, 0x00, 0x00));
        if($packet == false){
            $status["error"] = "Statistic packet error";
            return false;
        }
        $data = substr($packet["payload"], 11);//splitnum + 2 int
        $data = explode("\x00\x00\x01player_\x00\x00", $data);

        if(count($data) !== 2){
            $status["error"] = "Data error";
            return false;
        }
        $status["players"] = explode("\x00", substr($data[1], 0, -2));
        $data = explode("\x00", $data[0]);
        $last = false;
        foreach($data as $val){
            if($last){
                $status[$last] = $val;
                $last = false;
            }else{
                $last = $val;
            }
        }
		// Parse "plugins", if any
        if($status["plugins"]){
            $plugins = explode(": ", $status["plugins"], 2);
            $Info["raw_plugins"] = $plugins;
            $Info["software"] = $plugins[0];
            if(count($plugins) == 2){
                $status["plugins"] = explode("; ", $plugins[1]);
            }
        }else{
            $status["software"] = "Vanilla";
        }
        $status["isset_query"] = true;
        return true;
    }
    public function getPingStatus($socket, &$result){
        $pingPacket = "\x01" . "\x00\x00\x00\x00\x00\x00\x00\x00" . "\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78";
        //packetId + long(0) + magic
        fwrite($socket, $pingPacket);
        $packet = fread($socket, 65535);
        if(!$packet){
            return false;
        }
        $data = explode(";", substr($packet, 1 + 8 + 8 + 16 + 2));
        foreach($data as $offset => $value){
            switch($offset){
                case 0:
                    $result["game_id"] = $value;
                    break;
                case 1:
                    $result["hostname"] = $value;
                    break;
                case 2:
                    $result["protocol"] = $value;
                    break;
                case 3:
                    $result["version"] = $value;
                    break;
                case 4:
                    $result["numplayers"] = $value;
                    break;
                case 5:
                    $result["maxplayers"] = $value;
                    break;
                case 6:
                    $result["serverId"] = $value;
                    break;
                case 7:
                    $result["software"] = $value;
                    break;
                case 8:
                    $result["gametype"] = $value;
                    break;
            }
        }
        $result["isset_ping"] = true;
        return true;
    }
    public function resolveSRV(){
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
    public function writePacket(&$socket, $command, $append = ""){
        $command = "\xFE\xFD".chr($command).pack("c*", 0x01, 0x02, 0x03, 0x04).$append;
        fwrite($socket, $command);
        $data = fread($socket, 65535);
        if(!$data){
            return false;
        }
        if(strlen($data) < 5 || $data[0] != $command[2]){
            return false;
        }
        return $this->readPacket($data);
    }
    public function readPacket($buffer){
        $redata = [];
        $redata["packetType"] = ord($buffer{0});
        $redata["sessionID"] = unpack("N", substr($buffer, 1, 4))[1];
        $redata["payload"] = substr($buffer, 5);
        return $redata;
    }
}
