<?php

namespace App\Http\Controllers;

use Exception;
use Illuminate\Http\Request;
use Spatie\Crypto\Rsa\KeyPair;
use Spatie\Crypto\Rsa\PublicKey;
use Spatie\Crypto\Rsa\PrivateKey;

class RSAController extends Controller
{
    public function encrypt(Request $request)
    {
        $request->validate([
            'data' => 'required|string'
        ]);

        try {
            $privateKey = PrivateKey::fromFile(storage_path('rsa/private.key'));
            $encryptedData = base64_encode($privateKey->encrypt($request->input('data')));

            return response()->json(['data' => $encryptedData],200);
        } catch (Exception $exception) {
            return response()->json(['message' => $exception->getMessage()],422);
        }
    }

    public function decrypt(Request $request)
    {
        $request->validate([
            'data' => 'required|string'
        ]);

        try {
            $publicKey = PublicKey::fromFile(storage_path('rsa/public.key'));
            $decryptedData = $publicKey->decrypt(base64_decode($request->input('data')));

            return response()->json(['data' => $decryptedData],200);
        } catch (Exception $exception) {
            return response()->json(['message' => $exception->getMessage()],422);
        }
    }

    public function generateKeys(Request $request)
    {
        (new KeyPair())->generate(storage_path('rsa/private.key'), storage_path('rsa/public.key'));

        return 'ok';
    }
}
