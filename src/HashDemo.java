import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;


public class HashDemo {

	public HashDemo() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * Encode the plain text to given type of hash string
	 * 
	 * @param text the plain text to be hashed
	 * @param type the hash algorithm name from {md5, sha-1, sha-256, sha-384, sha-512}
	 * @return the hashed string
	 * @throws NoSuchAlgorithmException
	 */
	public static final String HashTextEncode(final String text, final String type) throws NoSuchAlgorithmException {
	    final String algorithm = type;
	    
	    // Create MD5 Hash
        MessageDigest digest = java.security.MessageDigest.getInstance(algorithm);
        digest.update(text.getBytes());
        byte[] messageDigest = digest.digest();

        return toHexString(messageDigest);
	}
	
	/**
	 * Converts byte array to hex string
	 * 
	 * @param bytes the byte array
	 * @return the converted hex string
	 */
	public static String toHexString(byte[] array) {
	    return DatatypeConverter.printHexBinary(array);
	}
	
	/**
	 * Converts hex string to byte array
	 * 
	 * @param hexString the hex string
	 * @return the converted byte array
	 */
	public static byte[] toByteArray(String s) {
	    return DatatypeConverter.parseHexBinary(s);
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String text = "This is my test string.";
		String textEncoded = "";
		try {
			textEncoded = HashDemo.HashTextEncode(text, "sha-1");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		}
		System.out.println(textEncoded);
		
	}

}
