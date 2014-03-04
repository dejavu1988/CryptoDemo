import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


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
	
	public static byte[] dsaSign(byte[] priKeyBytes, byte[] data) throws 
	NoSuchAlgorithmException, InvalidKeySpecException, 
	InvalidKeyException, SignatureException {
		PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(priKeyBytes);
		KeyFactory fact = KeyFactory.getInstance("DSA");
		PrivateKey priKey = fact.generatePrivate(priKeySpec);
		
		Signature dsa = Signature.getInstance("SHA1withDSA");
		dsa.initSign(priKey);
		dsa.update(data);
		byte[] signature = dsa.sign();
		return signature;
	}
	
	public static boolean dsaVerify(byte[] pubKeyBytes, byte[] sigToVerify, byte[] data) throws 
	NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException{
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
		KeyFactory fact = KeyFactory.getInstance("DSA");
		PublicKey pubKey = fact.generatePublic(pubKeySpec);
		
		Signature sig = Signature.getInstance("SHA1withDSA");
		sig.initVerify(pubKey);
		sig.update(data);
		boolean verifies = sig.verify(sigToVerify);
		return verifies;
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
		System.out.println("Pub: "+ HashDemo.toHexString(kp[0]));
		System.out.println("Pri: "+ HashDemo.toHexString(kp[1]));
		
		FileInputStream fis = null;
		byte[] data = null;
		try {
			fis = new FileInputStream("spongycastle.tar.gz");
			BufferedInputStream bufin = new BufferedInputStream(fis);
			data = new byte[bufin.available()];
			bufin.read(data);
			bufin.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] signature = null;
		try {
			signature = dsaSign(kp[1], data);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| InvalidKeySpecException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Signature: " + HashDemo.toHexString(signature));
		boolean verifies = false;
		try {
			verifies = dsaVerify(kp[0], signature, data);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| InvalidKeySpecException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Verifies: " + verifies);
	}

}
