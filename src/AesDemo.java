import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * https://stackoverflow.com/questions/8622367/what-are-best-practices-for-using-aes-encryption-in-android
 * @author xzgao
 *
 */
public class AesDemo {

	//public static final String PROVIDER = "BC";
    public static final int SALT_LENGTH = 20;
    public static final int IV_LENGTH = 16;
    public static final int PBE_ITERATION_COUNT = 1000;
    public static final int KEY_LENGTH = 256;

    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    private static final String PBE_ALGORITHM = "PBKDF2";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "AES";
    private static final String HMAC_KEY_ALGORITHM = "HMACSHA256";
    
    private static byte[] salt;
    private static byte[] secretKey;
    
	public AesDemo() {
	}
	
	public static String[] encrypt(byte[] secret, byte[] cleartext) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	InvalidAlgorithmParameterException, IllegalBlockSizeException, 
	BadPaddingException, UnsupportedEncodingException {
		
		// Generate IV
		byte[] iv = generateIv();
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        
        // Split secret to key1 and key2
        byte[] key1 = new byte[KEY_LENGTH/8];
        byte[] key2 = new byte[KEY_LENGTH/8];
        System.arraycopy(secret, 0, key1, 0, key1.length);
        System.arraycopy(secret, key1.length, key2, 0, key2.length);        
        SecretKey secretKey1 = new SecretKeySpec(key1, 0, key1.length, SECRET_KEY_ALGORITHM);
        
        // Encrypt
        Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey1, ivspec);
        byte[] encryptedText = encryptionCipher.doFinal(cleartext);
        // HMAC of encrypted text
        String hmac = HmacDemo.hmac(encryptedText, key2, HMAC_KEY_ALGORITHM);
        
        // Build output: iv + encryptedText
        byte[] encrypted = new byte[iv.length + encryptedText.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(encryptedText, 0, encrypted, iv.length, encryptedText.length);
        
        String[] out = {Base64.encodeBase64URLSafeString(encrypted), hmac};
        return out;
	}

	public static String decrypt(byte[] secret, String[] encrypted) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	InvalidAlgorithmParameterException, IllegalBlockSizeException, 
	BadPaddingException, UnsupportedEncodingException {
		
		// Get IV and encryptedText
		byte[] encryptedBytes = Base64.decodeBase64(encrypted[0]);
		byte[] iv = new byte[IV_LENGTH];
		byte[] encryptedText = new byte[encryptedBytes.length - IV_LENGTH];
		System.arraycopy(encryptedBytes, 0, iv, 0, iv.length);
		System.arraycopy(encryptedBytes, iv.length, encryptedText, 0, encryptedText.length);
		        
		// Split secret to key1 and key2
        byte[] key1 = new byte[KEY_LENGTH/8];
        byte[] key2 = new byte[KEY_LENGTH/8];
        System.arraycopy(secret, 0, key1, 0, key1.length);
        System.arraycopy(secret, key1.length, key2, 0, key2.length);        
        SecretKey secretKey1 = new SecretKeySpec(key1, 0, key1.length, SECRET_KEY_ALGORITHM);
        
        // HMAC of encrypted text
        String hmac = HmacDemo.hmac(encryptedText, key2, HMAC_KEY_ALGORITHM);
        System.out.println("HMAC2: " + hmac);
        if (!hmac.equals(encrypted[1])) {
        	throw new IllegalArgumentException("HMAC not matching");
        }
        
        // Decrypt
		Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey1, ivspec);
        byte[] decryptedText = decryptionCipher.doFinal(encryptedText);
        String decrypted = new String(decryptedText, "UTF-8");
        return decrypted;
	}
	
	public static byte[] getSecretKey(char[] password, byte[] salt) throws 
	NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, PBE_ITERATION_COUNT, 2*KEY_LENGTH);
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        SecretKey tmp = factory.generateSecret(pbeKeySpec);
        //SecretKey secret = new SecretKeySpec(tmp.getEncoded(), SECRET_KEY_ALGORITHM);
        return tmp.getEncoded();
	}

	public static byte[] generateSalt() throws NoSuchAlgorithmException {
		SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
	}
	
	private static byte[] generateIv() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		String text = "This is my test string.";
		String password = "secret";
		String[] cipherText = {};
		String decipherText = "";
		
		try {
			salt = generateSalt();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Salt Generation Error");
			e.printStackTrace();
			System.exit(0);
		}
		
		try {
			secretKey = getSecretKey(password.toCharArray(), salt);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException
				| NoSuchProviderException e) {
			System.out.println("Key Generation Error");
			e.printStackTrace();
			System.exit(0);
		}
		
		
		try {
			cipherText = encrypt(secretKey, text.getBytes("UTF-8"));
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			System.out.println("Encryption Error");
			e.printStackTrace();
			System.exit(0);
		}
		System.out.println("CipherText: " + cipherText[0]);
		System.out.println("HMAC: " + cipherText[1]);
		
		try {
			decipherText = decrypt(secretKey, cipherText);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			System.out.println("Decryption Error");
			e.printStackTrace();
			System.exit(0);
		}			
		
		System.out.println(decipherText);
		
	}

}
