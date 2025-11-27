<?php

namespace App\Http\Controllers;

use FunnyDev\EmailFilter\EmailFilterSdk;
use Illuminate\Http\Request;

class EmailFilterController
{
    public function store(Request $request)
    {
        $request->validate([
            'email' => 'required|email'
        ]);
        $instance = new EmailFilterSdk();
        $result = $instance->validate(email: $request->input('email'), fast: false, score: true);

        /*
         * You could handle the response of validator here like:
         * if ($result['recommend']) {approve account action...} else {notice them}
         */

        return $result;
    }
}