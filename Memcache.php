<?php
/**
 * class implements MemcacheInterface if Memcache available in system
 *
 * @author val@filin.us
 */

namespace PhishCheck;


class Memcache extends \Memcache implements namespace\MemcacheInterface {
    function __construct(array $options=array()) {
        parent::__costruct();
    }

    private $isPersitent = false;
    /**
     * @return boolean
     */
    public function isPersistent() {
        return $this->isPersitent;
    }

    /**
     * raises exception if there were some non-data manipulation result code
     *
     * @return bool
     * @throws MemcacheFatalError
     */
    public function isSafeMemcacheError() {
        $mcResultCode = $this->getResultCode();
        if (in_array($mcResultCode, array(
            \Memcache::RES_SUCCESS,
            \Memcache::RES_STORED,
            \Memcache::RES_DELETED,
            \Memcache::RES_DATA_EXISTS,
            \Memcache::RES_NOTFOUND,
            \Memcache::RES_NOTSTORED,
            \Memcache::RES_END,
            \Memcache::RES_BUFFERED
        ))) {
            return true;
        }
        throw new namespace\MemcacheFatalError('Memcache Fatal Error ', $mcResultCode);
    }

    /**
     * @param string $key
     * @return mixed
     */
    public function get($key) {
        return parent::get($key);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @param int $timeout
     * @return mixed
     */
    public function set($key, $value, $timeout) {
        return parent::set($key, $value, null, $timeout);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @param int $timeout
     * @return boolean
     */
    public function add($key, $value, $timeout) {
        return parent::add($key, $value, null, $timeout);
    }


    /**
     * @param string $key
     * @param mixed $value
     * @param int $timeout
     * @return boolean
     */
    public function replace($key, $value, $timeout) {
        return parent::replace($key, $value, null, $timeout);
    }

} 