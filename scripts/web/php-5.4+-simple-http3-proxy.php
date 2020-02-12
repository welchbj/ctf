<?php
/**
 * This is a simple proxy for allowing tools designed for running against
 * pre-QUIC HTTP servers to make requests to HTTP3 servers.
 *
 * In its current state, this script is only forwarding on simple GET
 * requests, but can be easily modified to include other HTTP verbs, headers,
 * and other request metadata as the task at hand requires.
 *
 * Invoke this with:
 * mv php-5.4+-file-upload-exfil-server.php index.php
 * php -S localhost:80
 *
 * And then point your tool towards http://localhost
 */

$http3_client = '/opt/curl-http3';
$target = 'https://example-http3-site.com:8443';

$uri = $_SERVER['REQUEST_URI'];

// logging; remove this line if it gets too verbose
file_put_contents('php://stdout', 'Proxying request for ' . $uri);

echo shell_exec($http3_client . ' ' . $target . $uri);
