#!/usr/bin/env php

<?php
/**
 * References:
 *   RecursiveDirectoryIterator docs -- https://www.php.net/manual/en/class.recursivedirectoryiterator.php
 *   Custom filters -- https://stackoverflow.com/a/34289275
 *   Regex filename filter -- https://www.php.net/manual/en/class.recursivedirectoryiterator.php#97228
 *   Reading files line-by-line -- https://stackoverflow.com/a/13246630
 */

function find_needle($fpath, $needle) {
    $matches = array();
    $handle = fopen($fpath, 'r');

    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            if (strpos($line, $needle) !== false) {
                $matches[] = $line;
            }
        }
        fclose($handle);
    }

    return $matches;
}

$start = realpath('/home');
$needle = 'some string';

$iter = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(
        $start,
        FileSystemIterator::SKIP_DOTS |
        FileSystemIterator::FOLLOW_SYMLINKS
    ),
    RecursiveIteratorIterator::SELF_FIRST,
);

foreach ($iter as $finfo) {
    $fpath = $finfo->getPathName();
    echo $fpath . PHP_EOL;

    if (is_file($fpath)) {
        $matches = find_needle($fpath, $needle);
        if ($matches) {
            print_r($matches);
        }
    }
}
