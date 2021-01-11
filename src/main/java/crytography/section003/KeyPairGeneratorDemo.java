package crytography.section003;

import crytography.Util;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
public class KeyPairGeneratorDemo {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048); //Recommended Key Size
		final KeyPair kp = kpg.generateKeyPair();

		final PublicKey publicKey = kp.getPublic();
		final PrivateKey privateKey = kp.getPrivate();

		log.info("--------------------------");
		log.info("Public key {}", publicKey);
		log.info("--------------------------");
		log.info("Public key hex-encoded {} ", Util.convertByteToHexForNicePrinting(publicKey.getEncoded()));
		log.info("--------------------------");
		log.info("Private key {}", privateKey);
		log.info("--------------------------");
	}
}
