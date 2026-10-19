<?php
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
Route::get('/', fn()=>view('solo'));
Route::post('/protocol/{action}', function(Request $r,string $action) {
    abort_unless(in_array($action,['create','arm','checkin','status','disarm','evaluate','simulate']),404);
    $response=Http::timeout(45)->post('http://protocol-adapter:8080/'.$action,$r->json()->all());
    if (!$response->successful()) return response()->json($response->json(),422);
    // Disposable product telemetry only. Never read to decide protocol status.
    DB::statement('CREATE TABLE IF NOT EXISTS visits(action VARCHAR(20), at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
    DB::insert('INSERT INTO visits(action) VALUES (?)',[$action]);
    return response()->json($response->json());
});
