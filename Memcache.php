<?php
/**
 * class implements MemcacheInterface if Memcache available in system
 *
 * @author val@filin.us
 */

namespace PhishCheck;


class Memcached extends \Memcache implements MemcacheInterface {

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
} 