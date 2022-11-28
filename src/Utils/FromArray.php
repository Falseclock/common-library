<?php
declare(strict_types=1);

namespace Falseclock\Common\Lib\Utils;

use ReflectionClass;
use ReflectionProperty;

abstract class FromArray
{
    /**
     * FromArray constructor.
     *
     * @param array|object|null $data
     */
    public function __construct($data = null)
    {
        if (isset($data)) {

            $reflect = new ReflectionClass($this);
            $props = $reflect->getProperties(ReflectionProperty::IS_PUBLIC | ReflectionProperty::IS_PROTECTED);

            foreach ($props as $prop) {

                $propertyName = $prop->getName();

                if (is_array($data) && isset($data[$propertyName]))
                    $this->$propertyName = $data[$propertyName];

                if (is_object($data) && isset($data->$propertyName))
                    $this->$propertyName = $data->$propertyName;
            }
        }
    }

    /**
     * @return false|string
     */
    public function toJson(): string
    {
        $reflect = new ReflectionClass($this);
        $props = $reflect->getProperties(ReflectionProperty::IS_PUBLIC);

        $data = [];
        foreach ($props as $prop) {
            $propertyName = $prop->getName();
            $data[$propertyName] = $this->$propertyName;
        }

        return json_encode($data, JSON_UNESCAPED_UNICODE);
    }
}
