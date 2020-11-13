<?php

declare(strict_types=1);

namespace mcpe;

use function chr;
use function count;
use function dns_get_record;
use function explode;
use function fclose;
use function fread;
use function fwrite;
use function ip2long;
use function ord;
use function pack;
use function preg_replace;
use function random_int;
use function stream_set_blocking;
use function stream_set_timeout;
use function stream_socket_client;
use function strlen;
use function substr;
use function unpack;
use const false;
use const DNS_SRV;
use const null;
use const true;

class Query{
    protected const RAKNET_MAGIC = "\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78";

    /** @var string */
    protected $ip;
    /** @var int */
    protected $port;
    /** @var int */
    protected $timeout;

    /** @var string */
    protected $clientId;

    /** @var resource */
    protected $socket = null;

    public function __construct(string $ip, int $port, int $timeout = 1){
        $this->ip = $ip;
        $this->port = $port;
        $this->timeout = $timeout;

        $this->resolveSRV();
        $this->newClientId();
    }

    public function connect() : void{
        $socket = @stream_socket_client("udp://" . $this->ip . ":" . $this->port, $errno, $errstr, $this->timeout);
        if($errno || $socket === false){
            throw new \RuntimeException("Socket connection error");
        }

        $this->socket = $socket;

        stream_set_timeout($this->socket, $this->timeout);
        stream_set_blocking($this->socket, true);
    }

    public function close() : void{
        fclose($this->socket);
    }

    /**
     * Regenerates client id.
     * Some servers can catch bots by zero-filled clientId and dont give back any server info.
     */
    public function newClientId() : void{
        $this->clientId = pack('ll', random_int(-0x7fffffff, 0x7fffffff), random_int(-0x7fffffff, 0x7fffffff));
    }

    public function getInfo() : \stdClass{
        $data = new \stdClass;

        $data->query = $this->getQueryInfo();
        $data->ping = $this->getPingInfo();

        return $data;
    }

    public function getQueryInfo() : \stdClass{
        $query = new \stdClass;

        $packet = $this->writePacket(9);

        if($packet === null){
            $query->error = "Challenge packet error";
            return $query;
        }

        $packet = $this->writePacket(0, pack("N", $packet["payload"]) . pack("c*", 0x00, 0x00, 0x00, 0x00));

        if($packet === null){
            $query->error = "Statistic packet error";
            return $query;
        }

        $data = substr($packet["payload"], 11); // "splitnum" + "\x00" + "\x80" + "\x00"
        $data = explode("\x00\x00\x01player_\x00\x00", $data);

        if(count($data) !== 2){
            $query->error = "Data error";
            return $query;
        }

        if($data[1] === "\x00"){
            $query->players = [];
        }else{
            $query->players = explode("\x00", substr($data[1], 0, -2));
        }

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

        // Parse "plugins"
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
        $pingPacket = "\x01" . "\x00\x00\x00\x00\x00\x00\x00\x00" . self::RAKNET_MAGIC . $this->clientId;
        //byte     + long         + magic + long
        //packetId + sendPingTime + magic + clientId

        fwrite($this->socket, $pingPacket);
        $packet = fread($this->socket, 65535);

        if($packet === false || $packet === ''){
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

    protected function resolveSRV() : void{
        $address = &$this->ip;

        if(ip2long($address) !== false){
            return;
        }

        $record = @dns_get_record("_minecraft._tcp.$address", DNS_SRV);
        if($record === false || count($record) === 0){
            return;
        }

        if(isset($record[0]["target"])){
            $address = $record[0]["target"];
        }
    }

    /**
     * @return int|string[]
     * @phpstan-return array{packetType: int, sessionID: int, payload: string}
     */
    protected function writePacket(int $command, string $append = "") : ?array{
        $command = "\xFE\xFD" . chr($command) . pack("c*", 0x01, 0x02, 0x03, 0x04) . $append;

        fwrite($this->socket, $command);

        $buffer = fread($this->socket, 65535);
        if($buffer === false || strlen($buffer) < 5 || $buffer[0] !== $command[2]){
            return null;
        }

        $redata = [];
        $redata["packetType"] = ord($buffer[0]);
        $redata["sessionID"] = unpack("N", substr($buffer, 1, 4))[1];
        $redata["payload"] = substr($buffer, 5);

        return $redata;
    }
}
