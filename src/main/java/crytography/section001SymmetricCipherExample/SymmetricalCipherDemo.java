package crytography.section001SymmetricCipherExample;

import crytography.Util;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
public class SymmetricalCipherDemo {

	/**
	 * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
 	 */
	private static final String ALGORITHM = "AES";
	private static final String CIPHER = "AES/CBC/PKCS5PADDING";

	public static String encrypt(byte[] key, byte[] initVector, String value) throws Exception {
		IvParameterSpec initializationVectorParameterSpec = new IvParameterSpec(initVector);
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, initializationVectorParameterSpec);
		byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(encrypted);
	}

	public static String decrypt(byte[] key, byte[] initVector, String encrypted) throws Exception {
		IvParameterSpec initializationVectorParameterSpec = new IvParameterSpec(initVector);
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, initializationVectorParameterSpec);
		byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
		return new String(original);
	}

	public static void main(String[] args) {
		try{
			//We generate a random key each time!!!
			SecureRandom sr = new SecureRandom(); //For properly getting a secure random
			byte[] key = new byte[16];

			//How to know the valid key size for AES algorithm
			//https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
			sr.nextBytes(key); // 128 bit key
			byte[] initVector = new byte[16];
			sr.nextBytes(initVector); // 16 bytes IV
			log.info("Random key={}", Util.convertByteToHexForNicePrinting(key));
			log.info("initVector={}", Util.convertByteToHexForNicePrinting(initVector));

			String payload = "E-Tuzel Team Rocks!!!!!";
			log.info("Original text=" + payload);

			String encrypted = encrypt(key, initVector, payload);
			log.info("Encrypted text={}" , encrypted);

			String decrypted = decrypt(key, initVector, encrypted);
			log.info("Decrypted text={}" , decrypted);

			String result = decrypted.equals(payload) ? "Success!" : "Failed.";
			log.info(result);
		} catch (Exception e){
			e.printStackTrace();
		}
	}
}
