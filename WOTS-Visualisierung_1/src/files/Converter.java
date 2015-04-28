package files;

//import java.security.SecureRandom;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.util.encoders.Hex;

public class Converter {
	
	// For testing purpose
	
	
//	public static void main(String[] args) {
//		
//		byte[] seed;
//		wots.WinternitzOTS instance = new wots.WinternitzOTS(42);
//		files.PseudorandomFunction prf = new files.AESPRF.AES128();
//		int n = prf.getLength();
//	    SecureRandom sRandom = new SecureRandom();
//	    seed = new byte[n];
//	    
//	    sRandom.nextBytes(seed);
//
//	    byte[] x = new byte[n];
//		
//	    sRandom.nextBytes(x);
//	    instance.init(prf, x);
//	    
//	    instance.generatePrivateKey(seed);
//	    
//	    byte[][] key = instance.getPrivateKey();
//	    
//	    System.out.println(_2dByteToHex(key));
//	    System.out.println(_byteToHex(key[0]));
//	    System.out.println("##############################");
//	    //System.out.println(key[0]);
//	    String output = _2dByteToHex(key);
//	    //System.out.println(output);
//	    
//	    byte[][] output2 = _stringTo2dByte(output, instance.getLength());
//	    
//	    System.out.println(_2dByteToHex(output2));
//	    
//	    System.out.println(_byteToHex(output2[0]));
//		
//	}
	
	/**
	 * Parses byte[][] to a Hex-String
	 * @param input
	 * @return
	 */
	public static String _2dByteToHex (byte[][] input) {
		
		String output = "";
		
		for (int i = 0; i < input.length; i++) {
	    	output += Hex.toHexString(input[i]);
	    }
		
		return output;
	}
	
	/**
	 * Parses byte[] to a Hex-String
	 * @param input
	 * @return
	 */
	public static String _byteToHex (byte[] input) {
		return Hex.toHexString(input);
	}
	
	/**
	 * Parses Hex-String to byte[][]
	 * @param input
	 * @return
	 */
	public static byte[][] _stringTo2dByte (String input, int l) {
		
		byte[][] output = new byte[l][];
		
		int s = input.length()/l;
		
		for (int i = 0; i < l; i++) {
			output[i] = _stringToByte(input.substring(i*s,s+i*s));
		}
		
		return output;
	}
	
	/**
	 * Parses Hex-String to byte[]
	 * @param input
	 * @return
	 */
	public static byte[] _stringToByte (String input) {
		return DatatypeConverter.parseHexBinary(input);
	}
}