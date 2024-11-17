//nopackage
import java.io.BufferedReader;
import java.io.FileReader;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;

public class ReconstructKeyPair {
    public static void main(String[] args) throws Exception {
        String privateKeyFilePath = "D:\\workspace2\\spring-jwt-app\\src\\main\\resources\\private.properties";
        String publicKeyFilePath = "D:\\workspace2\\spring-jwt-app\\src\\main\\resources\\public.properties";
        
        String privateKey = readFile(privateKeyFilePath);
        String publicKey = readFile(publicKeyFilePath);
        
        privateKey = privateKey
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\n", "")
            .trim();

        publicKey = publicKey
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\n", "")
            .trim();
            
        System.out.println(privateKey);
        System.out.println(publicKey);
        
        Decoder decoder = Base64.getMimeDecoder();

        byte[] private_key_array = decoder.decode(privateKey);
        byte[] public_key_array = decoder.decode(publicKey);

        // Reconstruct public key
        PrivateKey reconstructed_private_key = reconstruct_private_key("RSA", private_key_array);
        PublicKey reconstructed_public_key = reconstruct_public_key("RSA", public_key_array);
        
        System.out.println(reconstructed_private_key);
        System.out.println(reconstructed_public_key);

        KeyPair keyPair = new KeyPair(reconstructed_public_key, reconstructed_private_key);
        
        System.out.println(keyPair);
    }

    public static String readFile(String path) throws Exception {
        String everything;
        BufferedReader br = new BufferedReader(new FileReader(path));
        
        StringBuilder sb = new StringBuilder();
        String line = br.readLine();

        while (line != null) {
            sb.append(line);
            sb.append(System.lineSeparator());
            line = br.readLine();
        }
        everything = sb.toString();
    
        br.close();
        
        return everything;
    }
    
    public static PrivateKey reconstruct_private_key(String algorithm, byte[] private_key_array) {
        PrivateKey private_key = null;

        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec private_key_spec = new PKCS8EncodedKeySpec(private_key_array);
            private_key = kf.generatePrivate(private_key_spec);
        } catch(NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the private key, the given algorithm oculd not be found.");
        } catch(InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the private key");
            e.printStackTrace();
        }

        return private_key;
    }

    public static PublicKey reconstruct_public_key(String algorithm, byte[] pub_key) {
        PublicKey public_key = null;

        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec pub_key_spec = new X509EncodedKeySpec(pub_key);
            public_key = kf.generatePublic(pub_key_spec);
        } catch(NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm oculd not be found.");
        } catch(InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        }

        return public_key;
    }
}
