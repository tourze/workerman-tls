<?php

namespace Tourze\Workerman\TLS\Enum;

/**
 * TLS版本枚举
 */
enum TlsVersion: int
{
    case TLS_1_0 = 0x0301;
    case TLS_1_1 = 0x0302;
    case TLS_1_2 = 0x0303;
    case TLS_1_3 = 0x0304;
}
