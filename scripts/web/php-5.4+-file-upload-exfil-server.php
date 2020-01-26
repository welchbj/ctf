<?php
/**
 * IMPORTANT NOTE:
 * This server is wildly insecure and should only be used for one-off file
 * transfers to yourself.
 *
 * Invoke this with:
 * mv php-5.4+-file-upload-exfil-server.php index.php
 * php -S 0.0.0.0:8888
 */

define('FILE_FORM_FIELD', 'f');
define('MAX_FILE_SIZE', 1000000);
define('UPLOAD_DIR', './uploads');

header('Content-Type: text/plain; charset=utf-8');
header_remove('X-Powered-By');

function _log($msg) {
    file_put_contents('php://stdout', $msg . PHP_EOL);
}

try {
    if (!is_dir(UPLOAD_DIR)) {
        throw new RuntimeException('Uploads directory ' . UPLOAD_DIR .
                                   ' does not exist!');
    }

    $upload_dir = realpath(UPLOAD_DIR);

    _log('[INFO] Using uploads directory ' . $upload_dir);

    if (!isset($_FILES[FILE_FORM_FIELD])) {
        throw new RuntimeException('Received non-file-upload request');
    }

    if ($_FILES[FILE_FORM_FIELD]['size'] > MAX_FILE_SIZE) {
        throw new RuntimeException('Exceeded filesize limit');
    }

    $tmp_file_name = $_FILES[FILE_FORM_FIELD]['tmp_name'];
    $file_sha1 = sha1_file($_FILES[FILE_FORM_FIELD]['tmp_name']);
    $new_file_path = $upload_dir . '/' . $file_sha1;

    if (!move_uploaded_file($tmp_file_name, $new_file_path)) {
        throw new RuntimeException('Unable to move uploaded file');
    }

    _log('[INFO] Uploaded file now present at ' . $new_file_path);
    http_response_code(201);
} catch (RuntimeException $e) {
    _log('[ERROR] ' . $e->getMessage());
    http_response_code(404);
}
