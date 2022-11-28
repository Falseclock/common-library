<?php
declare(strict_types=1);

namespace Falseclock\Common\Lib\Utils;

class ArrayUtils
{
    /**
     * Проверка массива на ассоциативность
     *
     * @param array $array
     * @return bool
     */
    public static function isAssociative(array $array): bool
    {
        if ([] === $array)
            return false;

        return array_keys($array) !== range(0, count($array) - 1);
    }
}
