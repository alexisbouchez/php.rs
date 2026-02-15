<?php

namespace Illuminate\Support\Traits;

use Closure;

trait MiniEnumeratesValues
{
    protected $escapeWhenCastingToString = false;

    protected static $proxies = [];

    protected function getArrayableItems($items)
    {
        if (is_array($items)) {
            return $items;
        }
        return [];
    }

    public function toArray()
    {
        return $this->all();
    }
}
