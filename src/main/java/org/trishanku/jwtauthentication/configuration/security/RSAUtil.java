package org.trishanku.jwtauthentication.configuration.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

@Service
public class RSAUtil {

    private final String publicKeyExponent;
    private final String publicKeyModulus;
    private final String privateKeyExponent;
    private final String privateKeyModulus;

    public RSAUtil(@Value("${publicKey.exponent}")  String publicKeyExponent, @Value("${publicKey.modulus}") String publicKeyModulus,
                   @Value("${privateKey.exponent}") String privateKeyExponent, @Value("${privateKey.modulus}") String privateKeyModulus) {
        this.publicKeyExponent = publicKeyExponent;
        this.publicKeyModulus = publicKeyModulus;
        this.privateKeyExponent = privateKeyExponent;
        this.privateKeyModulus = privateKeyModulus;
    }

    public PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(privateKeyModulus), new BigInteger(privateKeyExponent));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(privateKeySpec);
    }

    public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(publicKeyModulus), new BigInteger(publicKeyExponent));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }
}
