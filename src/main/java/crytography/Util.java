package crytography;

public class Util {

	public static String convertByteToHexForNicePrinting(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for(byte b : bytes){
			sb.append(String.format("%02X ", b));
		}
		return sb.toString();
	}
}
