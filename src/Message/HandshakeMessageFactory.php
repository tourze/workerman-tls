<?php

namespace Tourze\Workerman\TLS\Message;

use Tourze\Workerman\TLS\Enum\HandshakeType;

/**
 * 握手消息工厂
 */
class HandshakeMessageFactory
{
    /**
     * 创建握手消息
     */
    public static function createMessage(HandshakeType $type, array $params): HandshakeMessage
    {
        return match($type) {
            HandshakeType::CLIENT_HELLO => new ClientHello(
                $params['version'],
                $params['random'],
                $params['session_id'],
                $params['cipher_suites'],
                $params['compression_methods'],
                $params['extensions'] ?? []
            ),
            HandshakeType::SERVER_HELLO => new ServerHello(
                $params['random'],
                $params['cipher_suite'],
                $params['version'],
                $params['session_id'],
                $params['compression_method'],
                $params['extensions'] ?? []
            ),
            HandshakeType::CERTIFICATE => new Certificate(
                $params['certificate']
            ),
            HandshakeType::SERVER_KEY_EXCHANGE => new ServerKeyExchange(
                $params['public_key'],
                $params['curve_type'],
                $params['curve_value'],
                $params['signature_algorithm'],
                $params['signature']
            ),
            HandshakeType::SERVER_HELLO_DONE => new ServerHelloDone(),
            HandshakeType::CLIENT_KEY_EXCHANGE => new ClientKeyExchange(
                $params['public_key']
            ),
            HandshakeType::CERTIFICATE_VERIFY => new CertificateVerify(
                $params['signature'],
                $params['signature_algorithm']
            ),
            HandshakeType::FINISHED => new Finished(
                $params['verify_data']
            ),
            // TLS 1.3 specific messages
            HandshakeType::ENCRYPTED_EXTENSIONS => new EncryptedExtensions(
                $params['extensions'] ?? []
            ),
            HandshakeType::NEW_SESSION_TICKET => new NewSessionTicket(
                $params['ticket_lifetime'],
                $params['ticket_age_add'],
                $params['ticket_nonce'],
                $params['ticket'],
                $params['extensions'] ?? []
            ),
            HandshakeType::KEY_UPDATE => new KeyUpdate(
                $params['request_update']
            ),
            default => throw new \InvalidArgumentException("Unsupported message type: {$type->name}")
        };
    }
}
