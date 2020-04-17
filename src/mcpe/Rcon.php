<?php

declare(strict_types=1);

namespace mcpe;

use function fread;
use function fsockopen;
use function fwrite;
use function pack;
use function stream_set_timeout;
use function strlen;
use function unpack;

class Rcon{
    public const PACKET_COMMAND        = 2;
    public const PACKET_LOGIN          = 3;
    public const PACKET_LOGGER         = 4;
    public const PACKET_PROTOCOL_CHECK = 9;

    public const RESPONSE_COMMAND = 0;
    public const RESPONSE_LOGIN   = 2;

    /** @var string */
    protected $host;
    /** @var int */
    protected $port;
    /** @var int */
    protected $timeout;

    /** @var resource */
    protected $socket;

    /** @var bool */
    protected $authorized = false;
    /** @var bool */
    protected $connected = false;
    /** @var string */
    protected $lastResponse = '';
    /** @var int */
    protected $currentRequestId = 0;

    /** @var bool */
    public $errno = false;
    /** @var string */
    protected $errstr = "";

    public function __construct(string $host, int $port, int $timeout = 10){
        $this->host = $host;
        $this->port = $port;
        $this->timeout = $timeout;
    }

    public function connect() : void{
        $socket = @fsockopen($this->host, $this->port, $errno, $errstr, $this->timeout);
        if($socket === false || $errno){
            $this->connected = false;

            $this->errno = $errno;
            $this->errstr = $errstr;

            return;
        }

        $this->socket = $socket;

        stream_set_timeout($this->socket, 3, 0);
        $this->connected = true;
    }

    public function isConnected() : bool{
        return $this->connected;
    }

    private function disconnect() : void{
        fclose($this->socket);
    }

    public function authorize(string $password) : bool{
        if(!$this->isConnected()){
            return false;
        }

        $this->writePacket(++$this->currentRequestId, self::PACKET_LOGIN, $password);
        $response_packet = $this->readPacket();
        if(
            $response_packet !== null and
            $response_packet['requestid'] === $this->currentRequestId and
            $response_packet['response'] === self::RESPONSE_LOGIN //TODO: This is check is useless, because server sends this as 2 every time
        ){
            $this->authorized = true;
            return true;
        }

        // Server sends requestid-field as -1 if login failed

        $this->disconnect();
        return false;
    }

    public function sendCommand(string $command) : ?string{
        if(!$this->isConnected()){
            return null;
        }

        $this->writePacket(++$this->currentRequestId, self::PACKET_COMMAND, $command);
        $response_packet = $this->readPacket();
        if(
            $response_packet !== null and
            $response_packet['requestid'] === $this->currentRequestId and
            $response_packet['response'] === self::RESPONSE_COMMAND
        ){
            return $this->lastResponse = $response_packet['payload'];
        }

        return null;
    }

    private function writePacket(int $requestID, int $packetType, string $packetBody) : void{
        if(!$this->isConnected()){
            return;
        }

        $packet = pack('VV', $requestID, $packetType) . $packetBody . "\x00\x00";
        $packet = pack('V', strlen($packet)) . $packet;
        fwrite($this->socket, $packet, strlen($packet));
    }

    /**
     * @return int|string[]
     * @phpstan-return array{requestid: int, response: int, payload: string}
     */
    private function readPacket() : ?array{
        if(!$this->isConnected()){
            return null;
        }

        $size_packed = fread($this->socket, 4);
        if($size_packed === false){
            return null;
        }

        $size = unpack("V", $size_packed)[1];

        $packet_serialized = fread($this->socket, $size);
        if($packet_serialized === false){
            return null;
        }

        return unpack('V1requestid/V1response/a*payload', $packet_serialized);
    }
}
