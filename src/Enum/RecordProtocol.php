<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS记录层协议类型枚举
 * 定义了TLS记录层中可能出现的协议类型
 */
enum RecordProtocol: int
{
    case CHANGE_CIPHER_SPEC = 20;  // 变更加密规范协议（切换加密算法）
    case ALERT = 21;               // 警报协议（传输错误通知）
    case HANDSHAKE = 22;           // 握手协议（协商安全参数）
    case APPLICATION_DATA = 23;    // 应用数据协议（加密后的业务数据）
}
