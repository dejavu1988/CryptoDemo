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
	 * (Hash-based Message Authentication Code) string
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
	public static String HmacTextEncode(String text, String key, String type) throws 
    UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {

	    SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), type);
	    Mac hmac = Mac.getInstance(type);
	    hmac.init(secretKey);
	
	    byte[] digest = hmac.doFinal(text.getBytes("UTF-8"));
	
	    return new String( Base64.encodeBase64(digest) );
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String text = "This is my test string.";
		String key = "secret";
		String encodedText = "";
		try {
			encodedText = HmacDemo.HmacTextEncode(text, key, "hmacsha512");
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
