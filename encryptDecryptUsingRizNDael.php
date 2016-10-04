<?php

class encryptDecryptUsingRizNDael{

    const PASSPHRASE = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const SALTVALUE = '!int3ll!50ft';
    const HASHALGORITHM = 'SHA1';
    const PASSWORDITERATIONS = 1;
    const INITVECTOR = 'e3b0c44298fc1c149afbf4c8996fb924';
    const KEYSIZE = 32;

    public static function encryptAuth($string) {
        $key = self::getKey(self::PASSPHRASE, self::SALTVALUE, self::PASSWORDITERATIONS, self::KEYSIZE, self::HASHALGORITHM);
        $encryptedText = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $string, MCRYPT_MODE_CBC, self::INITVECTOR);
        return base64_encode($encryptedText);
    }

    public static function decryptAuth($encryptedString) {
        $key = self::getKey(self::PASSPHRASE, self::SALTVALUE, self::PASSWORDITERATIONS, self::KEYSIZE, self::HASHALGORITHM);
        $decodedText = base64_decode($encryptedString);
        $decryptedText = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $decodedText, MCRYPT_MODE_CBC, self::INITVECTOR), "\0");
        return $decryptedText;
    }

    public static function getKey($passPhrase, $saltValue, $passwordIterations, $keySize, $hashAlgorithm) {
        $hl = strlen(hash($hashAlgorithm, null, true));
        $kb = ceil($keySize / $hl);
        $dk = '';
        for ($block = 1; $block <= $kb; $block ++) {
            $ib = $b = hash_hmac($hashAlgorithm, $saltValue . pack('N', $block), $passPhrase, true);
            for ($i = 1; $i < $passwordIterations; $i ++)
                $ib ^= ($b = hash_hmac($hashAlgorithm, $b, $passPhrase, true));
            $dk .= $ib;
        }
        return substr($dk, 0, $keySize);
    }

}
