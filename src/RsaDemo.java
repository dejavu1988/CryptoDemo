import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class RsaDemo {

	public RsaDemo() {
		// TODO Auto-generated constructor stub
	}

	public static byte[][] generateRsaKeyPair() throws 
	NoSuchAlgorithmException, InvalidKeySpecException, IOException{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();
		
		PublicKey pubKey = kp.getPublic();
		PrivateKey priKey = kp.getPrivate();
		
		System.out.println("Pub: "+pubKey.getFormat());
		System.out.println("Pub: "+priKey.getFormat());
		
		byte[][] res = {pubKey.getEncoded(), priKey.getEncoded()};
		return res;
	}
		
	public static byte[] rsaEncrypt(byte[] pubKeyBytes, byte[] data) throws
	IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
	InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException {
		
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PublicKey pubKey = fact.generatePublic(pubKeySpec);
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] cipherData = cipher.doFinal(data);
		return cipherData;
	}	
	
	public static byte[] rsaDecrypt(byte[] priKeyBytes, byte[] data) throws
	IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
	InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException {
		
		PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(priKeyBytes);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey priKey = fact.generatePrivate(priKeySpec);
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, priKey);
		byte[] decryptedData = cipher.doFinal(data);
		return decryptedData;
	}
	
			
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String plaintext = "This is a test sentence.";
		
		byte[][] kps = null;
		try {
			kps = generateRsaKeyPair();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] encrypted = null;
		try {
			encrypted = rsaEncrypt(kps[0], plaintext.getBytes("UTF-8"));
			System.out.println("Encrypted: "+ new String(encrypted, "UTF-8"));
		} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | NoSuchAlgorithmException
				| InvalidKeySpecException | NoSuchPaddingException
				| UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//byte[] decrypted;
		try {
			//decrypted= rsaDecrypt(kps[1], encrypted);
			String encryptedText = new String(encrypted, "UTF-8");
			String res = "";
	        while(encryptedText.length() > 64){
	          String chunk = encryptedText.substring(0, 64);
	          byte[] decrypted = rsaDecrypt(kps[1], chunk.getBytes("UTF-8"));
	          res += new String(decrypted, "UTF-8");
	          encryptedText = encryptedText.substring(64);
	        }
	        byte[] decrypted = rsaDecrypt(kps[1], encryptedText.getBytes("UTF-8"));
	        res += new String(decrypted, "UTF-8");
			System.out.println("Decrypted: "+ res);
		} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | NoSuchAlgorithmException
				| InvalidKeySpecException | NoSuchPaddingException
				| UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
}
