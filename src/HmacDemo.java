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

	public static String HmacTextEncode(String text, String key, String type) throws 
    UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {

	    SecretKeySpec secretKey = new SecretKeySpec((key).getBytes("UTF-8"), type);
	    Mac hmac = Mac.getInstance(type);
	    hmac.init(secretKey);
	
	    byte[] bytes = hmac.doFinal(text.getBytes("UTF-8"));
	
	    return new String( Base64.encodeBase64(bytes) );
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
