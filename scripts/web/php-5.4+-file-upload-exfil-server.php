<?php

define('FILE_FORM_FIELD', 'f');
define('MAX_FILE_SIZE', 1000000);

header('Content-Type: text/plain; charset=utf-8');

function _log($msg) {
    file_put_contents('php://stdout', $msg . PHP_EOL);
}

try {
    if (!isset($_FILES[FILE_FORM_FIELD])) {
        throw new RuntimeException('Received non-file-upload request');
    }

    if ($_FILES[FILE_FORM_FIELD]['size'] > MAX_FILE_SIZE) {
        throw new RuntimeException('Exceeded filesize limit.');
    }

    // yes, trusting client mime is bad
    $mime = $_FILES[FILE_FORM_FIELD]['mime'];
    $ext = explode('/', $mime)[1];

    $tmp_file_name = $_FILES[FILE_FORM_FIELD]['tmp_name'];
    $file_sha1 = sha1_file($_FILES[FILE_FORM_FIELD]['tmp_name']);
    $new_file_name = sprintf('./uploads/%s.%s', $file_sha1, $ext);

    if (!move_uploaded_file($tmp_file_name, $new_file_name)) {
        throw new RuntimeException('Unable to move uploaded file');
    }

    _log('[INFO] Uploaded file now present at ' . realpath($new_file_name));
} catch (RuntimeException $e) {
    _log('[ERROR] ' . $e->getMessage());
}
