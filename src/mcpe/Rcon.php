<?php

namespace mcpe;

class Rcon {
    protected $info = [],
    $socket,
    $authorized = false,
    $connected = false,
    $lastResponse = '';

    public $errno = false,
    $errstr = "";

    const PACKET_AUTHORIZE = 5;
    const PACKET_COMMAND = 6;
    const PACKET_STATUS = 8;
    const SERVERDATA_AUTH = 3;
    const SERVERDATA_UNCONNECT = 5;
    const SERVERDATA_STATUS = 6;
    const SERVERDATA_AHUTDOWN = 7;
    const SERVERDATA_AUTH_RESPONSE = 2;
    const SERVERDATA_EXECCOMMAND = 2;
    const SERVERDATA_RESPONSE_VALUE = 0;
    public function __construct($host, $port, $timeout = 10){
        $this->info["host"] = $host;
        $this->info["port"] = $port;
        $this->info["timeout"] = $timeout;
    }
    public function connect(){
        $this->socket = @fsockopen($this->info["host"], $this->info["port"], $errno, $errstr, $this->info["timeout"]);
        if(!$this->socket || $errno){
            $this->errno = $errno;
            $this->errstr = $errstr;
            return;
        }
        stream_set_timeout($this->socket, 3, 0);
        $this->connected = true;
    }
    public function isConnected(){
        return $this->connected;
    }
    public function disconnect(){
        if($this->socket){
            fclose($this->socket);
        }
    }
    public function sendCommand($command){
        if(!$this->isConnected()){
            return false;
        }
        $this->writePacket(self::PACKET_COMMAND, self::SERVERDATA_EXECCOMMAND, $command);
        $response_packet = $this->readPacket();
        if($response_packet['id'] == self::PACKET_COMMAND){
            if($response_packet['type'] == self::SERVERDATA_RESPONSE_VALUE){
                $this->lastResponse = $response_packet['body'];
                return $response_packet['body'];
            }
        }
        return false;
    }
    public function getStatus(){
        if(!$this->isConnected()){
            return false;
        }
        $this->writePacket(self::PACKET_STATUS, self::SERVERDATA_STATUS, $command);
        $response_packet = $this->readPacket();
        if($response_packet['id'] == self::PACKET_STATUS){
            if($response_packet['type'] == self::SERVERDATA_RESPONSE_VALUE){
                $this->lastResponse = $response_packet['body'];
                return unserialize($response_packet['body']);
            }
        }
        return [];
    }
    public function authorize(string $password){
        if(!$this->isConnected()){
            return false;
        }
        $this->writePacket(self::PACKET_AUTHORIZE, self::SERVERDATA_AUTH, $password);
        $response_packet = $this->readPacket();
        if($response_packet['type'] == self::SERVERDATA_AUTH_RESPONSE){
            if($response_packet['id'] == self::PACKET_AUTHORIZE){
                $this->authorized = true;
                return true;
            }
        }
        $this->disconnect();
        return false;
    }
    private function writePacket($packetId, $packetType, $packetBody){
        if(!$this->isConnected()){
            return false;
        }
        $packet = pack('VV', $packetId, $packetType);
        $packet = $packet.$packetBody."\x00";
        $packet = $packet."\x00";
        $packet_size = strlen($packet);
        $packet = pack('V', $packet_size).$packet;
        fwrite($this->socket, $packet, strlen($packet));
    }
    private function readPacket(){
        if(!$this->isConnected()){
            return false;
        }
        $size_data = fread($this->socket, 4);
        $size_pack = unpack('V1size', $size_data);
        $size = $size_pack['size'];
        $packet_data = fread($this->socket, $size);
        $packet_pack = unpack('V1id/V1type/a*body', $packet_data);
        return $packet_pack;
    }
}
