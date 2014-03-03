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

public class AesDemo {

	//public static final String PROVIDER = "BC";
	private static final int SALT_LENGTH = 20;
	private static final int IV_LENGTH = 16;
	private static final int PBE_ITERATION_COUNT = 1000;
	private static final int KEY_LENGTH = 256;

    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    private static final String PBE_ALGORITHM = "PBKDF2";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "AES";
    private static final String HMAC_KEY_ALGORITHM = "HMACSHA256";
    
    private static byte[] salt = null;
    private static byte[] secretKey = null;
    
	public AesDemo() {
	}
	
	/**
	 * Encrypts text using secret key with AES-256 algorithm
	 * after secret key is generated.
	 * 
	 * @param text the cleartext to be encrypted
	 * @return the 2-element String array: the 1st element is ciphertext
	 * , the 2nd element is the HMAC of ciphertext.
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public static String[] encryptGivenKey(byte[] text) throws 
	InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
	InvalidAlgorithmParameterException, IllegalBlockSizeException, 
	BadPaddingException, UnsupportedEncodingException {
		return encrypt(secretKey, text);
	}
	
	/**
	 * Decrypts the encrypted text using secret key with AES-256 algorithm
	 * after secret key is generated.
	 * 
	 * @param ciphertext the 2-element String array: the 1st element is ciphertext
	 * , the 2nd element is the HMAC of ciphertext.
	 * @return decrypted byte array
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] decryptGivenKey(String[] ciphertext) throws 
	InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
	InvalidAlgorithmParameterException, IllegalBlockSizeException, 
	BadPaddingException, UnsupportedEncodingException {
		return decrypt(secretKey, ciphertext);
	}
	
	/**
	 * Encrypts text using secret key with AES-256 algorithm.
	 * 
	 * @param secret the secret key in byte array
	 * @param text the cleartext to be encrypted
	 * @return the 2-element String array: the 1st element is ciphertext
	 * , the 2nd element is the HMAC of ciphertext.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public static String[] encrypt(byte[] secret, byte[] text) throws 
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
        System.out.println("SecretKey in ENC: " + HmacDemo.toHexString(secretKey1.getEncoded()));
        // Encrypt
        Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey1, ivspec);
        byte[] encryptedText = encryptionCipher.doFinal(text);
        // HMAC of encrypted text
        String hmac = HmacDemo.hmac(encryptedText, key2, HMAC_KEY_ALGORITHM);
        
        // Build output: iv + encryptedText
        byte[] encrypted = new byte[iv.length + encryptedText.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(encryptedText, 0, encrypted, iv.length, encryptedText.length);
        
        String[] out = {Base64.encodeBase64URLSafeString(encrypted), hmac};
        return out;
	}

	/**
	 * Decrypts the encrypted text using secret key with AES-256 algorithm.
	 * 
	 * @param secret the secret key in byte array
	 * @param encrypted the 2-element String array: the 1st element is ciphertext
	 * , the 2nd element is the HMAC of ciphertext.
	 * @return decrypted byte array
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] decrypt(byte[] secret, String[] encrypted) throws 
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
        System.out.println("SecretKey in DEC: " + HmacDemo.toHexString(secretKey1.getEncoded()));
        // HMAC of encrypted text
        String hmac = HmacDemo.hmac(encryptedText, key2, HMAC_KEY_ALGORITHM);
        System.out.println("HMAC2: " + hmac);
        if (!hmac.equalsIgnoreCase(encrypted[1])) {
        	throw new IllegalArgumentException("HMAC not matching");
        }
        
        // Decrypt
		Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey1, ivspec);
        byte[] decryptedText = decryptionCipher.doFinal(encryptedText);

        return decryptedText;
	}
	
	/**
	 * Prepares the secret key for AES encryption
	 * 
	 * @param passwd
	 * @return secret key in byte array
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException
	 * @throws IllegalArgumentException
	 */
	public static byte[] prepareSecretKey(String passwd) throws 
	NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException{
		secretKey = getSecretKey(passwd.toCharArray(), salt);
		if (secretKey == null) {
			throw new InvalidKeySpecException("Secret key is empty");
		}
		return secretKey;
	}
	
	/**
	 * Prepares salt
	 * @return salt in byte array
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] prepareSalt() throws NoSuchAlgorithmException {
		salt = generateSalt();
		if (salt == null) {
			throw new NoSuchAlgorithmException("Salt is empty");
		}
		return salt;
	}
	
	/**
	 * Prepare secret key byte array from given password and salt
	 * 
	 * @param password the char array of password
	 * @param salt salt in byte array
	 * @return the secret key in byte array
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException
	 * @throws IllegalArgumentException
	 */
	private static byte[] getSecretKey(char[] password, byte[] salt) throws 
	NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, PBE_ITERATION_COUNT, 2*KEY_LENGTH);
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        SecretKey tmp = factory.generateSecret(pbeKeySpec);
        //SecretKey secret = new SecretKeySpec(tmp.getEncoded(), SECRET_KEY_ALGORITHM);
        return tmp.getEncoded();
	}

	/**
	 * Generate the salt
	 * 
	 * @return salt in byte array
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] generateSalt() throws NoSuchAlgorithmException {
		SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
	}
	
	/**
	 * Generate the IV
	 * 
	 * @return IV in byte array
	 * @throws NoSuchAlgorithmException
	 */
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
		String password = "gogogo";
		String[] cipherText = {};
		byte[] decipherText = null;
		
		try {
			prepareSalt();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Salt Generation Error");
			e.printStackTrace();
			System.exit(0);
		}
		
		try {
			prepareSecretKey(password);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException
				| NoSuchProviderException e) {
			System.out.println("Key Generation Error: " + e.getMessage());
			System.exit(0);
		}
		
		
		try {
			cipherText = encryptGivenKey(text.getBytes("UTF-8"));
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
			decipherText = decryptGivenKey(cipherText);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			System.out.println("Decryption Error");
			e.printStackTrace();
			System.exit(0);
		}			
		
		try {
			System.out.println(new String(decipherText, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
