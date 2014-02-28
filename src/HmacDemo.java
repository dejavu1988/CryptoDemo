import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;


public class HmacDemo {

	public HmacDemo() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * Encode the plain text to given type of HMAC 
	 * (Hash-based Message Authentication Code) string.
	 * The default algorithm is hmacsha256.
	 * 
	 * @param text the plain text to be encoded
	 * @param key the secret key string
	 * @param type the HMAC algorithm name from 
	 * {hmacmd5, hmacsha1, hmacsha256, hmacsha384, hmacsha512}
	 * 
	 * @return the encoded string
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static String hmac(byte[] text, byte[] key, String type) throws 
    UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
		String alg = type;
		if (type == null || type.isEmpty()) {
			alg = "hmacsha256";
		}
	    SecretKeySpec secretKey = new SecretKeySpec(key, alg);
	    Mac hmac = Mac.getInstance(alg);
	    hmac.init(secretKey);
	
	    byte[] digest = hmac.doFinal(text);
	
	    return new String( Base64.encodeBase64URLSafeString(digest) );
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String text = "This is my test string.";
		String keyPhrase = "secret";
		String encodedText = "";
		try {
			encodedText = HmacDemo.hmac(text.getBytes("UTF-8"), keyPhrase.getBytes("UTF-8"), "");
		} catch (InvalidKeyException e) {
			System.out.println("Invalid Key");
		} catch (UnsupportedEncodingException e) {
			System.out.println("Unsupported Encoding");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm");
		}
		System.out.println(encodedText);
	}

}
