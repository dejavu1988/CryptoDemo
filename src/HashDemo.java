import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;


public class HashDemo {

	public HashDemo() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * Encode the plain text to given type of hash string.
	 * If type is empty, the default algorithm "sha-256" is chosen.
	 * 
	 * @param text the plain text to be hashed
	 * @param type the hash algorithm name from {md5, sha-1, sha-256, sha-384, sha-512}
	 * @return the hashed string
	 * @throws NoSuchAlgorithmException
	 */
	public static String hash(byte[] text, String type) throws 
	NoSuchAlgorithmException {
		String alg = type;
		if (type == null || type.isEmpty()) {
			alg = "sha-256";
		}	    
	    // Create Hash
        MessageDigest digest = java.security.MessageDigest.getInstance(alg);
        digest.update(text);
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
		String text = "";
		String textEncoded = "";
		try {
			textEncoded = HashDemo.hash(text.getBytes(), "md5");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		}
		System.out.println(textEncoded);
		
	}

}
