import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;


public class DsaDemo {

	public DsaDemo() {
		// TODO Auto-generated constructor stub
	}

	public static byte[][] generateDsaKeyPair() throws 
	NoSuchAlgorithmException, InvalidKeySpecException, IOException{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		kpg.initialize(1024, random);
		KeyPair kp = kpg.genKeyPair();
		
		PublicKey pubKey = kp.getPublic();
		PrivateKey priKey = kp.getPrivate();
		
		byte[][] res = {pubKey.getEncoded(), priKey.getEncoded()};
		return res;
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		byte[][] kp = null;
		try {
			kp = generateDsaKeyPair();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException
				| IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Pub: "+ kp[0]);
		System.out.println("Pri: "+ kp[1]);
		
	}

}
