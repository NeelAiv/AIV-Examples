package com.security.security;

import org.apache.commons.io.IOUtils;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DecryptionCryptography {

    private Cipher cipher;

    public DecryptionCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.cipher = Cipher.getInstance("RSA");
    }

    public String decryptEmbedPass(String passKey) throws Exception {

        DecryptionCryptography ac = new DecryptionCryptography();
        PublicKey publicKey = ac.getPublic("/pub");
        String decrypted_msg = ac.decryptText(passKey, publicKey);
        return decrypted_msg;

    }

    public PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = IOUtils.toByteArray(DecryptionCryptography.class.getResourceAsStream(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public String decryptText(String msg, PublicKey key)
            throws InvalidKeyException, UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(msg.getBytes())));
    }

}
