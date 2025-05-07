<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS警报消息级别枚举
 * 定义了TLS协议中警报消息的严重程度
 */
enum AlertLevel: int
{
    case WARNING = 1;  // 警告级别（可恢复错误，如证书即将过期）
    case FATAL = 2;    // 致命级别（不可恢复错误，如协议版本不匹配）
}
