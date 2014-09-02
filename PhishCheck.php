<?php

/**
 * @author val@filin.us
 */

namespace PhishCheck ;

const PERSISTENT_ID = 'persistent_id';
const MC_HOST = 'host';
const MC_PORT = 'port';
const PT_TOKEN = 'pt_token';
const TIME_TO_LIVE = 'ttl';

const MC_CLASS = 'memcache_class';

const FILTER_BZIP2 = 'bzip2.decompress';
const FILTER_ZLIB = 'zlib.deflate';


abstract class PhishCheckException extends \Exception {
    protected $info=null;
    public function getInfo() { return $this->info; }
    public function setInfo($info) { $this->info = $info; }
}

class MemcacheFatalError extends PhishCheckException {}
class InstallationError extends MemcacheFatalError {}
class HttpException extends PhishCheckException {}
class InvalidPhishTagHeaders extends PhishCheckException {}
class CacheException extends PhishCheckException {}
class UnknownError extends  PhishCheckException {}
class InputError extends PhishCheckException {
    function __construct($message, $badUrl=null) {
        parent::__construct($message);
        $obj = new \stdClass();
        $obj->url = $badUrl;
        $this->setInfo($obj);
    }
};


class UrlUtils {
    /**
     * makes scheme and host name lowercase
     * makes url encoding by own way and lowercased
     * eliminate optional ports 80 and 443
     * remove username and passes, PhishTank don't save them
     *
     * @param $rawUrl
     * @return string
     * @throws InputError
     */
    static public function normalizeUrl($rawUrl) {
        $error = static::getUrlError($rawUrl);
        if ($error!==false) {

            $parsed = parse_url($rawUrl);
            $scheme = strtolower($parsed['scheme']);
            $url = $scheme.'://';
            $url .= strtolower($parsed['host']);

            if (isset($parsed['port'])) {
                $port = $parsed['port'];
                if (!($port==80 && $scheme=='http')
                && !($port==443 && $scheme=='https')) {
                    $url .= ':'.$port;
                }
            }
            if (isset($parsed['path'])) {
                $url .= $parsed['path'];
                //$url .= urlencode(urldecode($parsed['path']));
            }

            if (isset($parsed['query'])) {
                $url .= '?'.urlencode(urldecode($parsed['query']));
            } else if (parse_url($url.'z',PHP_URL_QUERY)!==null) { // provoke to discover trailing '?'
                $url .= '?';
            }

            if (isset($parsed['fragment'])) {
                $url .= '#'.urlencode(urldecode($parsed['fragment']));
            } else if (parse_url($url.'z',PHP_URL_FRAGMENT)!==null) { // provoke to discover trailing '#'
                $url .= '#';
            }

            return $url;
        } else {
            throw new namespace\InputError($error);
        }

    }

    static public function getUrlError($url) {
        if (empty($url)) {
            return 'empty input';
        }

        if (filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_HOST_REQUIRED)===false) {
            return 'not RFC 2396 url';
        }

        $parsedUrl = parse_url($url);
        if (empty($parsedUrl)) {
            return 'not RFC 3986 url';
        }

        if (!isset($parsedUrl['scheme']) || !preg_match('/^https?$/i',$parsedUrl['scheme'])) {
            return 'not an http/https protocol';
        }

        if (!isset($parsedUrl['port'])) {
            $port = (int) filter_var($parsedUrl['port'], FILTER_VALIDATE_INT);
            if ($port<1 || $port>65535) {
                return 'port value is not an integer between 1 and 65535';
            }
        }

        $host = $parsedUrl['host'];

        if (strlen($host)<4) {
            return 'hostname is too short';
        }

        if (preg_match('/^\[(.*)\]|/$', $host, $matches)) { // content in square brackets is ipv6 candidate
            $ipv6 = $matches[1];
            if (filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)===false
            || filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)===false) {
                return 'not a valid/reachable ipv6 address';
            }
        } elseif (preg_match('/^((?:.+\.)?\d+)/$', $host, $matches)) { // ipv4 candidate
            $ipv4 = $matches[1];
            if (filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)===false
            || filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)===false
            || filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)===false) {
                return 'not a valid/reachable ipv4 address or public domain';
            }
        }

        return false; // no errors
    }

}

/**
 * Interface MemcacheInterface allows implement memcache useing either Memcache and Memcached
 * @package PhishCheck
 */
interface MemcacheInterface {
    /**
     * @param string $key
     * @return mixed
     */
    public function get($key);

    /**
     * @param string $key
     * @param mixed $value
     * @param int $timeout
     * @return mixed
     */
    public function set($key, $value, $timeout);

    /**
     * @param string $key
     * @param mixed $value
     * @param int $timeout
     * @return boolean
     */
    public function add($key, $value, $timeout);

    /**
     * @param string $key
     * @param mixed $value
     * @param int $timeout
     * @return boolean
     */
    public function replace($key, $value, $timeout);

    /**
     * raises exception if there were some non-data manipulation result code
     *
     * @return bool
     * @throws MemcacheFatalError
     */
    public function isSafeMemcacheError();

    /**
     * @return boolean
     */
    public function isPersistent();
}


class Cache {
    private $mcache;

    const HEADER_ETAG = 'etag';
    const HEADER_LAST_MODIFIED = 'last-modified';
    const HEADER_UTC = 'utc';

    const KEY_HEAD_REQUEST_RECENTLY = 'head-request-recently';
    const KEY_LAST_USED_ETAG = 'last-used-etag';
    const KEY_LAST_USED_UTC = 'last-used-utc';

    // 7 < 15
    const TIMEOUT_HEAD_REQUEST_CURL = 7;
    const TIMEOUT_HEAD_REQUEST_PENDING = 15;
    const TIMEOUT_HEAD_REQUEST_CHECKED = 60;
    const TIMEOUT_LAST_USED_BIG_FILE= 2000000; //23 days

    protected $options = array(
        namespace\PERSISTENT_ID=>'phishtankpool',
        namespace\MC_HOST=>'127.0.0.1',
        namespace\MC_PORT => 11211,
        namespace\PT_TOKEN => false, //'app for opendns'
        namespace\TIME_TO_LIVE => self::TIMEOUT_LAST_USED_BIG_FILE,
        namespace\MC_CLASS=>'Memcached'
    );

    /**
     * safely include proxy file for one on Memcache implementation
     *
     * @param string $className
     * @return bool|string
     */
    protected static function loadProxyClass($className='Memcached') {
        $className = self::normalizeClassName($className);
        if ($className!='Memcache' && $className!='Memcached') {
            return 'Only Memcache and Memcached extensions/classes are supported. Unknown class '.$className;
        }
        if (class_exists("\\$className", false)) {
            $file = __DIR__ . DIRECTORY_SEPARATOR . "$className.php";
            $included = require $file;
        } else {
            return "class/extension $className not available. check PHP configuration";
        }

        if (!$included) {
            return "Unable include source file $file";
        }
        return false;
    }

    private static function normalizeClassName($className) {
        return ucfirst(strtolower((string)$className));
    }

    function __construct(array $options=array()) {

        if (!empty($options)) {
            $this->options = array_merge($this->options, $options);
        }

        $className = self::normalizeClassName($options[namespace\MC_CLASS]);
        $error = static::loadProxyClass($className);
        if (!empty($error)) {
            throw new InstallationError($error);
        }

//        if (!empty($options[namespace\PERSISTENT_ID])) {
//            $this->mcache = new $className($options[namespace\PERSISTENT_ID]); // namespace\$className
//        } else {
            $this->mcache = new $className();
//        }

        //$this->mcache->setOption(\Memcached::OPT_COMPRESSION, true);
        //$this->mcache->setOption(\Memcached::OPT_HASH, \Memcached::HASH_FNV1A_64);
        //$this->mcache->setOption(\Memcached::OPT_SERIALIZER, \Memcached::SERIALIZER_IGBINARY);

        $host=$options[MC_HOST];
        $port=intval($options[MC_PORT]);

        $this->mcache->addServer($host,$port);
    }

    private $fp;
    function __destruct() {
        if ($this->mcache!=null && !$this->mcache->isPersistent()) {
            $this->mcache->quit(); //will be ignored for pconnect
        }

        if (isset($this->fp)) {
            @fclose($this->fp);
        }
    }

    static protected function urlHashCode($url) {
        return hash('sha256', $url);
    }

    private static $decompressionFilter;
    protected static function getBestDecompressionFilter() {
        if (self::$decompressionFilter!==null) {
            return self::$decompressionFilter;
        }

        $streamFilters = stream_get_filters();
        if (in_array('bzip2.*', $streamFilters)) {
            return self::$decompressionFilter = FILTER_BZIP2;
        } elseif (in_array('zlib.*', $streamFilters)) {
            return self::$decompressionFilter = FILTER_ZLIB;
        } else {
            return self::$decompressionFilter = false;
        };
    }

    /**
     * @return array
     * @throws HttpException
     */
    protected function requestETagAndLastModifiedByHEAD() {
        $url = $this->getDataUrl();
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'HEAD'); // HTTP request is 'HEAD'
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($ch, CURLOPT_TIMEOUT, static::TIMEOUT_HEAD_REQUEST_CURL);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Connection: Keep-Alive',
            'Keep-Alive: 300'
        ));
        $allHeaders = @curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        unset($ch);

         switch ($httpCode) {
            case 200:
                return self::extractEssentialHeaders($allHeaders);
            case 0:
                throw new HttpException('network problem to get ETag');
            default:
                throw new HttpException("unexpected site response code $httpCode");
         }
    }

    /**
     * @return string
     * @throws HttpException, InvalidPhishTagHeaders
     */
    protected function extractETagAndLastModifiedFromStreamMetaData(array $metaData=array()) {
        if (isset($metaData['wrapper_type']) && $metaData['wrapper_type'] != 'http') {
            return false;
        }
        if (empty($metaData['wrapper_data'])) {
            throw new UnknownError('there is no wrapper_data in metaData. very strange');
        }
        $wrapper_data = $metaData['wrapper_data'];
        $statusLine = array_shift($wrapper_data);
        if (!preg_match('/^HTTP\/1\.[01]\s(\d\d\d)\s(.+)/i', $statusLine, $matches)) {
            throw new HttpException('bad server response from that service');
        }

        list(,$httpCode,$reasonPhrase) = $matches;
        if ($httpCode != '200') {
            throw new HttpException("unexpected site response code $httpCode");
        }

        return self::extractEssentialHeaders($wrapper_data);
    }

    /**
     * extracts ETag and Last-Modified header from all headers and calculate UTC value of Last-Modified
     * function makes some basic validation and may raise exception
     *
     * @param $allHeaders array|string
     * @return array
     * @throws InvalidPhishTagHeaders
     */
    function extractEssentialHeaders($allHeaders) {
        if (!empty($allHeaders)) {
            $token = (is_array($allHeaders)) ? reset($allHeaders) : strtok($allHeaders, "\r\n");
            $result = array();
            while ($token!==false) {
                if (preg_match('/^(ETag|Last-Modified)\:(.*)$/iS', $token, $matches)) {
                    $headerName = strtolower($matches[1]);
                    if (isset($result[$headerName])) {
                        throw new InvalidPhishTagHeaders("Ambiguous header $headerName");
                    }
                    $headerValue = trim($matches[2]);
                    if (empty($headerValue)) {
                        throw new InvalidPhishTagHeaders("Missed value for header $headerName");
                    }
                    if ($headerName===self::HEADER_LAST_MODIFIED) {
                        date_default_timezone_set('UTC');
                        $utc = strtotime($headerValue); //Returns a timestamp on success, FALSE otherwise. Previous to PHP 5.1.0, this function would return -1 on failure.
                        if ($utc === false) { // we ignore old php versions
                            throw new InvalidPhishTagHeaders("Unable get time from Last-Modified");
                        }
                        $result[self::HEADER_UTC] = $utc;
                    }
                    $result[$headerName] = $headerValue;
                    if (sizeof($result)===3) {
                        return $result;
                    }
                }
                $token = (is_array($allHeaders)) ? next($allHeaders) : strtok("\r\n");
            }
        }
        throw new InvalidPhishTagHeaders('ETag or Last-Modified header is absent');
    }

    /**
     * @return void;
     */
    public function updateIfNecessary() {
        $mc = $this->mcache; // shorthand

        $wasHeadRequestActivityRecently = $mc->get(self::KEY_HEAD_REQUEST_RECENTLY);
        if ($wasHeadRequestActivityRecently) { // was HEAD recently done?
            return;
        }
        $mc->isSafeMemcacheError();

        $isCheckingStatus = $mc->add(self::KEY_HEAD_REQUEST_RECENTLY, 'updating', static::TIMEOUT_HEAD_REQUEST_PENDING);
        if ($isCheckingStatus===false) {
            // someone else won right to check headers and update database
            // we need wait if database is read and cached first time
            for ($i=static::TIMEOUT_HEAD_REQUEST_PENDING+1; $i>0; $i++) {
                sleep(1);
                if ($mc->get(self::KEY_LAST_USED_ETAG)!==false) {
                    break;
                }
            }
            return;
        }
        $mc->isSafeMemcacheError();

        try {
            $latest = $this->requestETagAndLastModifiedByHEAD();
            $headETag = $latest[self::HEADER_ETAG];
        } catch (PhishCheckException $e) {
            return;
        }

        $cacheETag = $mc->get(self::KEY_LAST_USED_ETAG);
        $mc->isSafeMemcacheError();
        if ($headETag ===  $cacheETag) {
            $mc->touch(self::KEY_HEAD_REQUEST_RECENTLY, static::TIMEOUT_HEAD_REQUEST_CHECKED);
            $mc->touch(self::KEY_LAST_USED_ETAG, static::TIMEOUT_LAST_USED_BIG_FILE);
            return;
        };

        $this->totalLoad($headETag);

        return;
    }

    /**
     * @var string
     */
    private $dataUrl;
    /**
     * can be used for GET, HEAD and build url with compression scheme
     * example:
     * http://data.phishtank.com/data/..token.../online-valid.csv.bz2
     *
     * @return string
     */
    protected function getDataUrl() {
        if (is_null($this->dataUrl)) {
            $url = 'http://data.phishtank.com/data/';
            if (!empty($this->options[PT_TOKEN])) {
                $url.= $this->options[PT_TOKEN].'/';
            }
            $url.= 'online-valid.csv';
            //$url = 'file://'.dirname(__FILE__).DIRECTORY_SEPARATOR.'verified_online.csv';
            //$url = 'http://www.ukr.net/';

            switch (self::getBestDecompressionFilter()) {
                case FILTER_BZIP2:
                    $url.='.bz2';
                    break;
                case FILTER_ZLIB:
                    $url.='.gz';
                    break;
            }
            $this->dataUrl = $url;
        }

        return $this->dataUrl;
    }

    protected function getLastUsedTag() {
        //$result = $this->mcache->get(static::LAST_USED_ETAG, null, $this->lastUsedEtagCAS);
        $result = $this->mcache->get(static::KEY_LAST_USED_ETAG);
        return $result;
    }

    /**
     *
     * @param string $eTag
     * @return resource
     * @throws HttpException
     */
    protected function getStreamForTotalLoad($eTag=null) {
        $url = $this->getDataUrl();

        /*
                [0] => HTTP/1.1 200 OK
                [1] => Date: Fri, 01 Aug 2014 07:19:52 GMT
                [2] => Server: Apache/2.2.9 (Debian) PHP/5.2.6-1+lenny9 with Suhosin-Patch
                [3] => X-Powered-By: PHP/5.2.6-1+lenny9
                [4] => X-Request-Limit-Interval: 10800 Seconds
                [5] => X-Request-Limit: 12
                [6] => X-Request-Count: 3
                [7] => Last-Modified: Fri, 01 Aug 2014 07:00:00 GMT
                [8] => ETag: "Fri, 01 Aug 2014 07:00:00"
                [9] => Content-Disposition: attachment; filename=verified_online.csv.bz2
                [10] => Connection: close
                [11] => Content-Type: text/csv
                 */

        $httpOptions = array(
            'max_redirects' => '0',
            'ignore_errors' => '1'
        );
        if (!empty($eTag)) {
            $httpOptions['header'] = 'If-None-Match: '.$eTag;
        }

        $streamHttpContext = stream_context_create(array('http' => $httpOptions ));

        $fp = @fopen($url, 'r', false, $streamHttpContext);
        if (!$fp) {
            throw new HttpException('Unable open stream from url '+$url);
        }

        $this->fp = $fp; // in case of further exception destructor will close this stream

        $decompressionFilter =  self::getBestDecompressionFilter();
        if ($decompressionFilter) {
            stream_filter_append($fp, $decompressionFilter, STREAM_FILTER_READ);
        }

        return $fp;
    }

    /**
     * resets memcache
     */
    public function resetCache() {
        $this->mcache->flush();
    }

    /**
     * loads phishtank database and saves itto memcache
     *
     * @param null $eTag
     */
    public function totalLoad($eTag=null) {
        $fp = $this->getStreamForTotalLoad($eTag);

        if( $fp ) {
            $mc = $this->mcache;
            $mc->setOption(\Memcached::OPT_BUFFER_WRITES, true);
            $mc->setOption(\Memcached::OPT_NO_BLOCK, true);

            $metaData = @stream_get_meta_data($fp);
            $arr = self::extractETagAndLastModifiedFromStreamMetaData($metaData);
            $eTag = $arr[self::HEADER_ETAG];
            $utc = $arr[self::HEADER_UTC];
            $stored = $mc->set(self::KEY_LAST_USED_ETAG, $eTag, static::TIMEOUT_LAST_USED_BIG_FILE);

            $csv_fields = @fgetcsv($fp); // skip csv header
            $ttl = $this->options[TIME_TO_LIVE];

            $prevKey = null;

            $array = fgetcsv($fp);
            $phases = array('add', 'replace' /*, 'set'*/);
            foreach($phases as $phase) {
                if ($array) {
                    do {
                        list ($phishNo, $phishUrl) = $array;
                        try {
                            $normalizedUrl = namespace\UrlUtils::normalizeUrl($phishUrl);
                        } catch (PhishCheckException $e) {
                            error_log("unable put to memcache".$e->getMessage());
                        }
                        $key = self::urlHashCode($normalizedUrl);
                        $value = array($phishNo, $normalizedUrl, $utc);
                        if ($mc->$phase($key, $value, $ttl)) {
                            continue;
                        } elseif ($mc->isSafeMemcacheError()) {
                            break;
                        }
                    } while ($array = @fgetcsv($fp));
                }
            }

            @fclose($fp);
            unset($this->fp);

            $stored = $mc->set(self::KEY_LAST_USED_UTC, $utc, static::TIMEOUT_LAST_USED_BIG_FILE);
        }
    }

    /**
     * @param $rawUrl
     * @return array
     * @throws HttpException
     */
    public function getUrlInfo($rawUrl) {
        $normalizedUrl = namespace\UrlUtils::normalizeUrl($rawUrl);
        $isPhish = false;
        $result = array(
            'url' => $rawUrl,
            'normalizedUrl'=>$normalizedUrl
        );

        $this->updateIfNecessary();

        $hashKey = static::urlHashCode($normalizedUrl);
        $cached = $this->mcache->get($hashKey);

        $this->mcache->isSafeMemcacheError();

        if ($cached!==false) { // phish found
            list ($phishNo, $phishUrl, $utc) = $cached;
            $lastUsedUtc = $this->mcache->get(self::KEY_LAST_USED_UTC);
            $this->mcache->isSafeMemcacheError();
            $isNotLongerPhish = ($lastUsedUtc!==false && $lastUsedUtc>$utc);

            if (!$isNotLongerPhish) { // phish was confirmed by recent data update
                $isPhish = TRUE;
            }

            $result['phishTankID'] = $phishNo;
        }
        $result['phish'] = $isPhish;
        return $result;
    }

}


