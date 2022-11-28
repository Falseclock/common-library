<?php
declare(strict_types=1);

namespace Falseclock\Common\Lib\Utils;

class ClassUtils
{
    /**
     * @param string|object|mixed $classname
     *
     * @return false|string
     */
    public static function className($classname): string
    {
        if (is_object($classname))
            $classname = get_class($classname);

        return (substr($classname, strrpos($classname, '\\') + 1));
    }
}
