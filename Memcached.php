<?php
/**
 * class implements MemcacheInterface if Memcached available in system
 *
 * @author val@filin.us
 */

namespace PhishCheck;


class Memcached extends \Memcached implements namespace\MemcacheInterface {

    function __construct(array $options=array()) {
        parent::__costruct();
        $this->setOption(\Memcached::OPT_BINARY_PROTOCOL, true);
        $this->setOption(\Memcached::OPT_RETRY_TIMEOUT, 1 );
        $this->setOption(\Memcached::OPT_LIBKETAMA_COMPATIBLE,  true );
        $this->setOption(\Memcached::OPT_TCP_NODELAY, true);
    }

    public function get($key) {
        return parent::get($key, null, $cas);
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
            \Memcached::RES_SUCCESS,
            \Memcached::RES_STORED,
            \Memcached::RES_DELETED,
            \Memcached::RES_DATA_EXISTS,
            \Memcached::RES_NOTFOUND,
            \Memcached::RES_NOTSTORED,
            \Memcached::RES_END,
            \Memcached::RES_BUFFERED
        ))) {
            return true;
        }
        throw new namespace\MemcacheFatalError('Memcache Fatal Error ', $mcResultCode);
    }
} 