<?php
namespace PhishCheck;

/**
 * @author val@filin.us
 */
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