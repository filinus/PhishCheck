<?php

/**
 * @author val@filin.us
 */

require __DIR__ . DIRECTORY_SEPARATOR . 'PhishCheck.php';


try {
    if (empty($_REQUEST['url']))
        throw new PhishCheck\InputError('no input url');

    $url=$_REQUEST['url'];

    $normalizedUrl = PhishCheck\UrlUtils::normalizeUrl($url);

    $checker = new PhishCheck\Cache(array(
        PhishCheck\PT_TOKEN=>'????????????????????????????????????????????????????????????????'
    ));

    $checkInfo = $checker->getUrlInfo($url);
    response(200, 'OK', $checkInfo);
} catch (PhishCheck\InputError $e){
    $message = $e->getMessage();
    $checkInfo = $e->getInfo();
    response(400, $e->getMessage(), $e->getInfo());
} catch (\Exception $e) {
    response(500, 'Error', sprintf('#%d %s',$e->getCode(),$e->getMessage()));
}

function response($httpCode, $phrase, $info) {
    header($phrase, true, $httpCode);
    header('Content-Type: application/json');

    $obj = new \stdClass();
    $obj->status = ((string)$httpCode=='200') ? 'success':'error';
    $obj->message = (string) $phrase;
    $obj->info = $info;

    $json = @json_encode($obj);
    echo $json;
}

