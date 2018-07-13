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
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;

class Decrypt {

    private Reader stream(String str, String pass) {
        File file;
        file = new File(str);

        // init password
        Boolean bUserPassword = (pass != "");
        if (!bUserPassword) {
            pass = "htc20100416";
        }

        try {
            System.err.println("Max key len: " + Cipher.getMaxAllowedKeyLength("AES"));
            System.err.println("Decrypting with password: " + pass);

            // key init

            // google replacement for Android N
            Key generateKey = new SecretKeySpec(
                InsecureSHA1PRNGKeyDerivator.deriveInsecureKey(pass.getBytes(), 192 / 8),
                "AES");

            // original code
            // KeyGenerator instance2 = KeyGenerator.getInstance("AES");
            // //SecureRandom instance3 = SecureRandom.getInstance("SHA1PRNG", new CryptoProvider());
            // SecureRandom instance3 = SecureRandom.getInstance("SHA1PRNG", "Crypto");
            // //SecureRandom instance3 = SecureRandom.getInstance("SHA1PRNG");
            // instance3.setSeed(pass.getBytes());
            // instance2.init(192, instance3);
            // Key generateKey = instance2.generateKey();

            // cipher init
            Cipher instance;

            if (bUserPassword) {
                instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
            } else {
                instance = Cipher.getInstance("AES");
            }

            // load iv if encrypted
            InputStream openInputStream;
            openInputStream = new FileInputStream(file);
            InputStream bufferedInputStream = new BufferedInputStream(openInputStream);

            // load additional init vector from the file
            if (bUserPassword) {
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
            } else {
                instance.init(2, generateKey);
            }

            openInputStream = new CipherInputStream(bufferedInputStream, instance);
            return new InputStreamReader(openInputStream);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void run(String file, String pass) {
        Reader reader = stream(file, pass);
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
        String pass = args.length > 1 ? args[1] : "";
        prog.run(args[0], pass);
    }
}
