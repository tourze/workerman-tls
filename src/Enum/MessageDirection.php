<?php

namespace Tourze\Workerman\TLS\Enum;

enum MessageDirection: string
{
    case CLIENT_TO_SERVER = 'client_to_server';
    case SERVER_TO_CLIENT = 'server_to_client';
    case BOTH = 'both';

    public function isValidFor(bool $isServer): bool
    {
        return match($this) {
            self::BOTH => true,
            self::CLIENT_TO_SERVER => $isServer,
            self::SERVER_TO_CLIENT => !$isServer
        };
    }
}
