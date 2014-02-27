import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class HashDemo {

	public HashDemo() {
		// TODO Auto-generated constructor stub
	}

	public static final String HashTextEncode(final String text, final String type) throws NoSuchAlgorithmException {
	    final String algorithm = type;
	    
	    // Create MD5 Hash
        MessageDigest digest = java.security.MessageDigest.getInstance(algorithm);
        digest.update(text.getBytes());
        byte messageDigest[] = digest.digest();

        // Create Hex String
        StringBuilder hexString = new StringBuilder();
        for (byte mDigest : messageDigest) {
            String h = Integer.toHexString(0xFF & mDigest);
            while (h.length() < 2){
            	h = "0" + h;
            }	                
            hexString.append(h);
        }
        return hexString.toString();
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
