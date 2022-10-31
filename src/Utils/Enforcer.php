<?php

namespace Falseclock\Common\Lib\Utils;

use ReflectionClass;
use Throwable;

class Enforcer
{
    const ABSTRACT_VALUE = "abstract";

    /**
     * @param $class
     * @param $c
     */
    public static function __add($class, $c) {
        try {

            $reflection = new ReflectionClass($class);
            $constantsForced = $reflection->getConstants();
            foreach($constantsForced as $constant => $value) {
                if(constant("$c::$constant") === Enforcer::ABSTRACT_VALUE) {
                    trigger_error("Undefined $constant in " . $c);
                }
            }
        }
        catch(Throwable $e) {
            trigger_error($e->getMessage());
        }
    }
}
