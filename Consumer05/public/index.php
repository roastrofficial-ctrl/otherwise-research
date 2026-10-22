<?php
use Illuminate\Http\Request;
if (PHP_SAPI === 'cli-server' && is_file(__DIR__.parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH)) && parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH)!=='/') return false;
define('LARAVEL_START', microtime(true));
require __DIR__.'/../vendor/autoload.php';
(require_once __DIR__.'/../bootstrap/app.php')->handleRequest(Request::capture());
