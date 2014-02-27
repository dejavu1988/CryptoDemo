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
    private static final String PBE_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "AES";
    
    
	public AesDemo() {
		// TODO Auto-generated constructor stub
	}
	
	public static String encrypt(SecretKey secret, String cleartext) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	InvalidAlgorithmParameterException, IllegalBlockSizeException, 
	BadPaddingException, UnsupportedEncodingException {
		
		byte[] iv = generateIv();
        String ivHex = HashDemo.toHexString(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
        byte[] encryptedText = encryptionCipher.doFinal(cleartext.getBytes("UTF-8"));
        String encryptedHex = HashDemo.toHexString(encryptedText);

        return ivHex + encryptedHex;
	}

	public static String decrypt(SecretKey secret, String encrypted) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	InvalidAlgorithmParameterException, IllegalBlockSizeException, 
	BadPaddingException, UnsupportedEncodingException {
		
		Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        String ivHex = encrypted.substring(0, IV_LENGTH * 2);
        String encryptedHex = encrypted.substring(IV_LENGTH * 2);
        IvParameterSpec ivspec = new IvParameterSpec(HashDemo.toByteArray(ivHex));
        decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
        byte[] decryptedText = decryptionCipher.doFinal(HashDemo.toByteArray(encryptedHex));
        String decrypted = new String(decryptedText, "UTF-8");
        return decrypted;
	}
	
	public static SecretKey getSecretKey(String password, byte[] salt) throws 
	NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, PBE_ITERATION_COUNT, KEY_LENGTH);
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        SecretKey tmp = factory.generateSecret(pbeKeySpec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), SECRET_KEY_ALGORITHM);
        return secret;
	}

	public static byte[] generateSalt() throws NoSuchAlgorithmException {
		SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        //String saltHex = HashDemo.toHexString(salt);
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
		SecretKey key = null;
		String cipherText = "";
		String decipherText = "";
		byte[] salt = null;
		
		try {
			salt = generateSalt();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Salt Generation Error");
			e.printStackTrace();
			System.exit(0);
		}
		System.out.println(HashDemo.toHexString(salt));
		
		try {
			key = getSecretKey(password, salt);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException
				| NoSuchProviderException e1) {
			System.out.println("Key Generation Error");
			e1.printStackTrace();
			System.exit(0);
		}
		
		
		try {
			cipherText = encrypt(key, text);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			System.out.println("Encryption Error");
			e.printStackTrace();
			System.exit(0);
		}
		System.out.println(cipherText);
		
		try {
			decipherText = decrypt(key, cipherText);
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
