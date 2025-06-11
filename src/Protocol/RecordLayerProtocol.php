<?php

namespace Tourze\Workerman\TLS\Protocol;

use Tourze\Workerman\PsrLogger\LogUtil;
use Tourze\Workerman\TLS\Context\ConnectionContext;
use Tourze\Workerman\TLS\Message\HandshakeMessage;
use Workerman\Connection\ConnectionInterface;
use Workerman\Connection\TcpConnection;
use Workerman\Protocols\ProtocolInterface;

class RecordLayerProtocol implements ProtocolInterface
{
    // Record Layer Content Types
    private const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
    private const CONTENT_TYPE_ALERT = 21;
    private const CONTENT_TYPE_HANDSHAKE = 22;
    private const CONTENT_TYPE_APPLICATION_DATA = 23;

    // TLS Record Header Size
    private const RECORD_HEADER_SIZE = 5;

    // Maximum TLS Record Size (16KB)
    private const MAX_RECORD_SIZE = 16384;

    // Connection contexts
    private static ?\WeakMap $connectionContexts = null;

    // Sequence numbers for each connection
    private static ?\WeakMap $sequenceNumbers = null;

    public static function init(): void
    {
        self::$connectionContexts = new \WeakMap();
        self::$sequenceNumbers = new \WeakMap();
        LogUtil::info('RecordLayerProtocol initialized');
    }

    /**
     * Input processing - checks message length and returns needed data length
     */
    public static function input(string $buffer, ConnectionInterface $connection): int
    {
        assert(!empty($buffer), 'Buffer cannot be empty');
        assert($connection instanceof TcpConnection, 'Connection must be TcpConnection');

        try {
            LogUtil::debug('Processing input buffer, length: ' . strlen($buffer));

            // Check if we have enough data for record header
            if (strlen($buffer) < self::RECORD_HEADER_SIZE) {
                return self::RECORD_HEADER_SIZE - strlen($buffer);
            }

            // Parse record header
            $recordHeader = unpack('Ctype/nversion/nlength', substr($buffer, 0, self::RECORD_HEADER_SIZE));
            assert(is_array($recordHeader) && isset($recordHeader['type'], $recordHeader['version'], $recordHeader['length']),
                'Invalid record header format');

            LogUtil::debug(sprintf(
                'Record header - type: %d, version: 0x%04X, length: %d',
                $recordHeader['type'],
                $recordHeader['version'],
                $recordHeader['length']
            ));

            // Validate record size
            if ($recordHeader['length'] > self::MAX_RECORD_SIZE) {
                throw new \Exception('Record size exceeds maximum allowed size');
            }

            // Return total needed length
            $totalLength = self::RECORD_HEADER_SIZE + $recordHeader['length'];
            if (strlen($buffer) < $totalLength) {
                return $totalLength - strlen($buffer);
            }

            return $totalLength;

        } catch  (\Throwable $e) {
            LogUtil::error("Record layer error", $e);
            $connection->close();
            return 0;
        }
    }

    /**
     * Decode record layer messages
     */
    public static function decode(string $buffer, ConnectionInterface $connection): string|HandshakeMessage
    {
        assert($connection instanceof TcpConnection);

        try {
            LogUtil::debug('Decoding record, buffer length: ' . strlen($buffer));

            $context = self::getConnectionContext($connection);

            // Parse record header
            $recordHeader = unpack('Ctype/nversion/nlength', substr($buffer, 0, self::RECORD_HEADER_SIZE));
            $payload = substr($buffer, self::RECORD_HEADER_SIZE);

            // Get sequence number for this connection
            $seqNum = self::getSequenceNumber($connection);
            LogUtil::debug("Using sequence number: $seqNum");

            // If encryption is active, decrypt the payload
            if ($context->isEncryptionActive()) {
                $payload = $context->decrypt($payload, $seqNum);
            }

            // If compression is active, decompress the payload
            if ($context->isCompressionActive()) {
                $payload = $context->decompress($payload);
            }

            // Verify MAC if encryption is active
            if ($context->isEncryptionActive()) {
                $mac = substr($payload, -$context->getMACSize());
                $data = substr($payload, 0, -$context->getMACSize());

                if (!$context->verifyMAC($data, $mac, $seqNum, $recordHeader['type'])) {
                    throw new \Exception('MAC verification failed');
                }

                $payload = $data;
            }

            // Increment sequence number
            self::incrementSequenceNumber($connection);

            // Handle different content types
            return match($recordHeader['type']) {
                self::CONTENT_TYPE_HANDSHAKE => HandshakeMessage::deserialize($payload),
                self::CONTENT_TYPE_CHANGE_CIPHER_SPEC => self::handleChangeCipherSpec($payload, $context),
                self::CONTENT_TYPE_ALERT => self::handleAlert($payload),
                self::CONTENT_TYPE_APPLICATION_DATA => $payload,
                default => throw new \Exception("Unknown content type: {$recordHeader['type']}")
            };

        } catch  (\Throwable $e) {
            LogUtil::error("Record layer decode error", $e);
            $connection->close();
            return '';
        }
    }

    /**
     * Encode record layer messages
     */
    public static function encode(mixed $data, ConnectionInterface $connection): string
    {
        assert($connection instanceof TcpConnection);

        try {
            $context = self::getConnectionContext($connection);
            $seqNum = self::getSequenceNumber($connection);

            // Determine content type
            $contentType = self::CONTENT_TYPE_APPLICATION_DATA;
            if ($data instanceof HandshakeMessage) {
                $contentType = self::CONTENT_TYPE_HANDSHAKE;
                $data = $data->serialize();
            }

            $payload = $data;

            // Calculate MAC if encryption is active
            if ($context->isEncryptionActive()) {
                $mac = $context->calculateMAC($payload, $seqNum, $contentType);
                $payload .= $mac;
            }

            // Compress if compression is active
            if ($context->isCompressionActive()) {
                $payload = $context->compress($payload);
            }

            // Encrypt if encryption is active
            if ($context->isEncryptionActive()) {
                $payload = $context->encrypt($payload, $seqNum);
            }

            // Increment sequence number
            self::incrementSequenceNumber($connection);

            // Split into records if payload exceeds max size
            if (strlen($payload) > self::MAX_RECORD_SIZE) {
                return self::splitIntoRecords($payload, $context, $contentType);
            }

            // Create record header
            $header = pack('Cnn',
                $contentType,
                $context->getNegotiatedVersion()->value,
                strlen($payload)
            );

            return $header . $payload;

        } catch  (\Throwable $e) {
            LogUtil::error("Record layer encode error", $e);
            $connection->close();
            return '';
        }
    }

    /**
     * Split large payloads into multiple records
     */
    private static function splitIntoRecords(string $payload, ConnectionContext $context, int $contentType): string
    {
        $result = '';
        $offset = 0;
        $length = strlen($payload);

        while ($offset < $length) {
            $chunk = substr($payload, $offset, self::MAX_RECORD_SIZE);
            $header = pack('Cnn',
                $contentType,
                $context->getNegotiatedVersion()->value,
                strlen($chunk)
            );
            $result .= $header . $chunk;
            $offset += self::MAX_RECORD_SIZE;
        }

        return $result;
    }

    /**
     * Handle ChangeCipherSpec message
     */
    private static function handleChangeCipherSpec(string $payload, ConnectionContext $context): string
    {
        if ($payload !== "\x01") {
            throw new \Exception("Invalid ChangeCipherSpec message");
        }

        // Activate encryption for subsequent records
        $context->activateEncryption();

        return $payload;
    }

    /**
     * Handle Alert message
     */
    private static function handleAlert(string $payload): string
    {
        if (strlen($payload) !== 2) {
            throw new \Exception("Invalid Alert message length");
        }

        $level = ord($payload[0]);
        $description = ord($payload[1]);

        LogUtil::warning(sprintf("Received Alert: level=%d, description=%d", $level, $description));

        return $payload;
    }

    /**
     * Get connection context
     */
    private static function getConnectionContext(ConnectionInterface $connection): ConnectionContext
    {
        if (!isset(self::$connectionContexts)) {
            self::init();
        }

        if (!isset(self::$connectionContexts[$connection])) {
            throw new \RuntimeException('No connection context found');
        }

        return self::$connectionContexts[$connection];
    }

    /**
     * Get sequence number for connection
     */
    private static function getSequenceNumber(ConnectionInterface $connection): int
    {
        if (!isset(self::$sequenceNumbers)) {
            self::init();
        }

        if (!isset(self::$sequenceNumbers[$connection])) {
            self::$sequenceNumbers[$connection] = 0;
        }

        return self::$sequenceNumbers[$connection];
    }

    /**
     * Increment sequence number for connection
     */
    private static function incrementSequenceNumber(ConnectionInterface $connection): void
    {
        if (!isset(self::$sequenceNumbers)) {
            self::init();
        }

        if (!isset(self::$sequenceNumbers[$connection])) {
            self::$sequenceNumbers[$connection] = 0;
        }

        self::$sequenceNumbers[$connection]++;
    }
}
