<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS握手状态枚举
 * 定义了TLS握手过程中可能出现的各个阶段
 */
enum HandshakeState: string
{
    // 初始状态
    case START = 'start';

    // 客户端状态 (TLS 1.2 & 1.3)
    case CLIENT_HELLO_SENT = 'client_hello_sent';
    case CLIENT_CERTIFICATE_SENT = 'client_certificate_sent';
    case CLIENT_FINISHED_SENT = 'client_finished_sent';

    // 客户端状态 (TLS 1.2)
    case CLIENT_KEY_EXCHANGE_SENT = 'client_key_exchange_sent';
    case CLIENT_CERTIFICATE_VERIFY_SENT = 'client_certificate_verify_sent';

    // 客户端状态 (TLS 1.3)
    case CLIENT_EARLY_DATA_SENT = 'client_early_data_sent';
    case CLIENT_END_OF_EARLY_DATA_SENT = 'client_end_of_early_data_sent';

    // 服务器状态 (TLS 1.2 & 1.3)
    case SERVER_HELLO_SENT = 'server_hello_sent';
    case SERVER_CERTIFICATE_SENT = 'server_certificate_sent';
    case SERVER_CERTIFICATE_REQUEST_SENT = 'server_certificate_request_sent';
    case SERVER_FINISHED_SENT = 'server_finished_sent';

    // 服务器状态 (TLS 1.2)
    case SERVER_KEY_EXCHANGE_SENT = 'server_key_exchange_sent';
    case SERVER_HELLO_DONE_SENT = 'server_hello_done_sent';

    // 服务器状态 (TLS 1.3)
    case SERVER_ENCRYPTED_EXTENSIONS_SENT = 'server_encrypted_extensions_sent';
    case SERVER_CERTIFICATE_VERIFY_SENT = 'server_certificate_verify_sent';
    case SERVER_NEW_SESSION_TICKET_SENT = 'server_new_session_ticket_sent';

    // 完成状态
    case HANDSHAKE_COMPLETED = 'handshake_completed';

    // 错误状态
    case ERROR = 'error';

    /**
     * 检查是否为TLS 1.3特有状态
     */
    public function isTls13Only(): bool
    {
        return match($this) {
            self::CLIENT_EARLY_DATA_SENT,
            self::CLIENT_END_OF_EARLY_DATA_SENT,
            self::SERVER_ENCRYPTED_EXTENSIONS_SENT,
            self::SERVER_CERTIFICATE_VERIFY_SENT,
            self::SERVER_NEW_SESSION_TICKET_SENT => true,
            default => false
        };
    }

    /**
     * 检查是否为TLS 1.2特有状态
     */
    public function isTls12Only(): bool
    {
        return match($this) {
            self::CLIENT_KEY_EXCHANGE_SENT,
            self::CLIENT_CERTIFICATE_VERIFY_SENT,
            self::SERVER_KEY_EXCHANGE_SENT,
            self::SERVER_HELLO_DONE_SENT => true,
            default => false
        };
    }
}
