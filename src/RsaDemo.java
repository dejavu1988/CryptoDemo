import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;


public class RsaDemo {

	public RsaDemo() {
		// TODO Auto-generated constructor stub
	}

	public static BigInteger[] generateRsaKeyPair() throws 
	NoSuchAlgorithmException, InvalidKeySpecException{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
		
		BigInteger[] res = {pub.getModulus(), pub.getPublicExponent(), 
				priv.getModulus(), priv.getPrivateExponent() };
		return res;
	}
	
	public static restorePubKey(byte[] m, byte[] e){
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(BigInteger(m), BigInteger(e));
	    KeyFactory fact = KeyFactory.getInstance("RSA");
	    PublicKey pubKey = fact.generatePublic(keySpec);
	}
	
		
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		BigInteger[] kps = null;
		try {
			kps = generateRsaKeyPair();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if(kps.length == 4){
			System.out.println("Pub_M " + kps[0]);
			System.out.println("Pub_E " + kps[1]);
			System.out.println("Priv_M " + kps[2]);
			System.out.println("Priv_E " + kps[3]);
		}
		
	}
	
}
