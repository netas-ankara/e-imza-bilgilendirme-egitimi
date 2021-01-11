package crytography.section002;

import crytography.Util;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Slf4j
public class HashingWithSalt {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		final String password = "AVerySecretPassword";
		final String salt = "SomeSaltText";
		final int iterations = 32; //Uniqueness
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 512);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] hashed = skf.generateSecret(keySpec).getEncoded();

		log.info("The SHA-256 value salted with PBKDF2 is {}", Util.convertByteToHexForNicePrinting(hashed));
	}
}
