<?php

declare(strict_types=1);

namespace Crutch\OpenSslCrypt;

use Crutch\Crypt\Crypt;

final class OpenSslCrypt implements Crypt
{
    private string $secret;
    private int $saltLen;
    private string $openSslAlgo;
    private string $hashAlgo;

    public function __construct(
        string $secret,
        int $saltLen,
        string $openSslAlgo = 'AES-256-CBC',
        string $hashAlgo = 'sha256'
    ) {
        $this->secret = $secret;
        $this->saltLen = max(16, $saltLen);
        $this->openSslAlgo = $openSslAlgo;
        $this->hashAlgo = $hashAlgo;
    }

    /**
     * @inheritDoc
     */
    public function encrypt(string $decrypted): string
    {
        $salt = openssl_random_pseudo_bytes($this->saltLen);
        $salted = '';
        $dx = '';
        while (strlen($salted) < 48) {
            $dx = hash($this->hashAlgo, $dx . $this->secret . $salt, true);
            $salted .= $dx;
        }

        $key = substr($salted, 0, 32);
        $iv  = substr($salted, 32, 16);
        $encrypted = openssl_encrypt($decrypted, $this->openSslAlgo, $key, 0, $iv);
        return base64_encode($salt . $encrypted);
    }

    /**
     * @inheritDoc
     */
    public function decrypt(string $encrypted): string
    {
        $decoded = base64_decode($encrypted);
        $salt = substr($decoded, 0, $this->saltLen);
        $ct = substr($decoded, $this->saltLen);

        $rounds = 3;
        $data = $this->secret . $salt;
        $parts = [hash($this->hashAlgo, $data, true)];
        $result = $parts[0];
        for ($i = 1; $i < $rounds; $i++) {
            $parts[$i] = hash($this->hashAlgo, $parts[$i - 1] . $data, true);
            $result .= $parts[$i];
        }
        $key = substr($result, 0, 32);
        $iv  = substr($result, 32, 16);

        return openssl_decrypt($ct, $this->openSslAlgo, $key, 0, $iv);
    }
}
