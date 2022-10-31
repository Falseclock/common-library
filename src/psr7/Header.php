<?php
declare(strict_types=1);

namespace Falseclock\Common\Lib\psr7;

use Falseclock\Common\Lib\Utils\Enforcer;

/**
 * Access-Control-Allow-Credentials: true
 * Access-Control-Allow-Headers: DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type
 * Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS, PATCH
 * Access-Control-Max-Age: 1728000
 * Cache-control: no-store
 * Content-Type: text/html; charset=UTF-8
 * Expires: Wed, 04 Aug 2021 11:46:44 GMT
 * Pragma: no-store
 * Date: Wed, 04 Aug 2021 11:46:44 GMT
 */
abstract class Header
{
    // Каждый дочерний класс должен определить наименование заголовка
    public const HEADER_NAME = Enforcer::ABSTRACT_VALUE;
    /** @var mixed Дополнительное значение к заголовку */
    protected $option;
    /** @var string */
    protected $value;

    /**
     * @param mixed $value
     */
    public function __construct($value, $option = null)
    {
        Enforcer::__add(__CLASS__, get_class($this));

        $this->value = $value;
        $this->option = $option;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this::HEADER_NAME;
    }

    /**
     * @return mixed
     */
    public function getValueWithOption()
    {
        return $this->value;
    }

    /**
     * Получение печатного варианта заголовка
     *
     * @return string
     */
    public function toString(): string
    {
        return sprintf("%s: %s", $this::HEADER_NAME, $this->value);
    }
}
