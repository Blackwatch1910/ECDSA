package org.dev.tech.MavenApp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONException;
import org.json.JSONObject;

/**
 *
 * @author metamug.com
 */
public class DigiSig {

    private static final String SPEC = "secp256k1";
    private static final String ALGO = "SHA256withECDSA";

    private JSONObject sender() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        ECGenParameterSpec ecSpec = new ECGenParameterSpec(SPEC);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair keypair = g.generateKeyPair();
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        String plaintext = "This is message";

        //...... sign
        Signature ecdsaSign = Signature.getInstance(ALGO);
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(plaintext.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
        String pub = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String sig = Base64.getEncoder().encodeToString(signature);
        System.out.println(sig);
        System.out.println(pub);

        JSONObject obj = new JSONObject();
        obj.put("publicKey", pub);
        obj.put("signature", sig);
        obj.put("message", plaintext);
        obj.put("algorithm", ALGO);

        return obj;
    }

    private boolean receiver(JSONObject obj) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        Signature ecdsaVerify = Signature.getInstance(obj.getString("algorithm"));
        KeyFactory kf = KeyFactory.getInstance("EC");

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(obj.getString("publicKey")));

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(obj.getString("message").getBytes("UTF-8"));
        boolean result = ecdsaVerify.verify(Base64.getDecoder().decode(obj.getString("signature")));

        return result;
    }
    
    public byte[] decode(String encodedString) {
    	byte[] decodedString = Base64.getDecoder().decode(encodedString.getBytes());
    	return decodedString;
    }

     public static void main(String[] args) throws IOException, JSONException{
        try {
            DigiSig digiSig = new DigiSig();
            JSONObject obj = digiSig.sender();
            System.out.println("\nThe old json Object is:\n" + obj);
            System.out.println("Message:" + obj.get("message"));
            boolean result = digiSig.receiver(obj);
            System.out.println(result);
            
            String x = new String(digiSig.decode("eyJtZXNzYWdlIjp7ImxpY2Vuc2VLZXkiOiJBVlZJLVVFWTgtR0hBVS1RV1BGIiwic2VydmVySWQiOiIyMC1FMC0xNi0wMS03OC1COCIsImV4cGlyZXMiOjE2MjE0MzYwMDYyOTl9LCJwdWJsaWNLZXkiOiJNRll3RUFZSEtvWkl6ajBDQVFZRks0RUVBQW9EUWdBRW1BYUJaNnF1MHZyVEdLbmhUTzk4dEtnT2c2VmxraVJMakNmcmRqb0tIOGtUNUErekowUjNuMzBKOCtGekF6L0tBYkpNb1UyTDcwMUU2TWd2eXNUVGhnPT0iLCJzaWduYXR1cmUiOiJNRVFDSUhaVVFZNE80NXNBVXJ4R2E1Vmp0a2Q2Wk12ZWYwOVZTMHlSb3BiYnQ5NDBBaUJFOGljSmhPK0Z2Rld0OXozcEphMjVRMGFjZWIveWxuVjhvZGFvN1loRzdBPT0iLCJhbGdvcml0aG0iOiJTSEEyNTZ3aXRoRUNEU0EifQ"));
            System.out.println("Decoded String:" + x);
            JSONObject jsonobj = new JSONObject(x);
            System.out.println("Message of decoded string:" + jsonobj.get("message"));
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DigiSig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DigiSig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DigiSig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(DigiSig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(DigiSig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DigiSig.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}