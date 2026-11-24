<?php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController {
  public function show(Request $request) {
    $name = $request->input('name');
    $users = DB::select("SELECT * FROM users WHERE name = '" . $name . "'"); // PHP-003
    DB::raw("DELETE FROM logs WHERE id = {$request->id}");
    $user = User::create($request->all());                                 // PHP-004
    $data = unserialize($request->cookie('data'));                         // PHP-007
    include($request->input('page') . '.php');                             // PHP-008
    $hash = md5($request->input('password'));                              // PHP-009
    $content = file_get_contents($request->input('url'));                  // PHP-012
    return view('profile', ['bio' => $request->input('bio')]);
  }
}
