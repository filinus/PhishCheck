<?php

function response($httpCode, $phrase, $info) {
    header($phrase, true, $httpCode);
    header('Content-Type: application/json');

    if (ob_get_level()) ob_end_clean();
    $obj = new \stdClass();
    $obj->status = ((string)$httpCode=='200') ? 'success':'error';
    $obj->message = (string) $phrase;
    $obj->info = $info;

    $json = @json_encode($obj);
    echo $json;
}

function myErrorHandler($errno, $errstr) {
    $data = array(
        'status'=>'error',
        'message'=>$errstr,
        'backtrace'=>debug_backtrace()
    );
    response(500,'Internal Server Error', $data);

}

require __DIR__ . DIRECTORY_SEPARATOR . 'PhishCheck.php';


try {
    $normalizedUrl = PhishCheck\UrlUtils::normalizeUrl($url);

    $checker = new PhishCheck\Cache(array(
        PhishCheck\PT_TOKEN=>'8a3f4dfd6b19accc25a8339a935f60a87de10190063d60b8d305e541499dfd11'
    ));
    $checker->resetCache();

    response(200, 'OK', 'cache been reset');
} catch (PhishCheck\InputError $e){
    $message = $e->getMessage();
    $info = $e->getInfo();
    response(400, $e->getMessage(), $e->getInfo());
} catch (\Exception $e) {
    response(500, 'Error', $e->getMessage());
}
