// need old apache harmony jdk to compile/run!
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Arrays;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Provider;

class Decrypt {

    // via https://stackoverflow.com/a/42337802/1496234
    /**
     * Implementation of Provider for SecureRandom. The implementation     supports the
     * "SHA1PRNG" algorithm described in JavaTM Cryptography Architecture, API
     * Specification & Reference
    */
    final class CryptoProvider extends Provider {
        /**
         * Creates a Provider and puts parameters
         */
        public CryptoProvider() {
            super("Crypto", 1.0, "HARMONY (SHA1 digest; SecureRandom; SHA1withDSA signature)");
            put("SecureRandom.SHA1PRNG",
                    "org.apache.harmony.security.provider.crypto.SHA1PRNG_SecureRandomImpl");
            put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
        }
    }

    private Reader stream(String str) {
        File file;
        file = new File(str);
        //String str2 = "htc20100416";
        String str2 = "pass";
        try {
            System.err.println("Max key len: " + Cipher.getMaxAllowedKeyLength("AES"));

            Cipher instance;
            InputStream openInputStream;
            KeyGenerator instance2 = KeyGenerator.getInstance("AES");
            //SecureRandom instance3 = SecureRandom.getInstance("SHA1PRNG", new CryptoProvider());
            SecureRandom instance3 = SecureRandom.getInstance("SHA1PRNG", "Crypto");
            //SecureRandom instance3 = SecureRandom.getInstance("SHA1PRNG");
            instance3.setSeed(str2.getBytes());
            instance2.init(192, instance3);
            Key generateKey = instance2.generateKey();
            //instance = Cipher.getInstance("AES");
            instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
            openInputStream = new FileInputStream(file);
            InputStream bufferedInputStream = new BufferedInputStream(openInputStream);
            byte[] bArr = new byte[16];
            int length = "HTCMSGBACKUP_V1".length();

            byte[] bArr2 = new byte[length];
            bufferedInputStream.mark(length + 16);
            bufferedInputStream.read(bArr2, 0, length);
            if (Arrays.equals(bArr2, "HTCMSGBACKUP_V1".getBytes())) {
                bufferedInputStream.read(bArr, 0, 16);
            } else {
                throw new Exception();
            }

            instance.init(2, generateKey, new IvParameterSpec(bArr));
            //instance.init(2, generateKey);
            openInputStream = new CipherInputStream(bufferedInputStream, instance);
            return new InputStreamReader(openInputStream);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void run(String file) {
        Reader reader = stream(file);
        BufferedReader bufferedReader = new BufferedReader(reader);
        try {
            for (String line = bufferedReader.readLine() ;
                 line != null;
                 line = bufferedReader.readLine()) {

                System.out.println(line);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String args[]){
        Decrypt prog = new Decrypt();
        prog.run(args[0]);
    }
}
