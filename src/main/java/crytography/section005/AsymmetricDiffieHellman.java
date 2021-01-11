package crytography.section005;

import crytography.Util;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

@SuppressWarnings ("DuplicatedCode")
@Slf4j
public class AsymmetricDiffieHellman {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, SignatureException {
		final String original = "Tuzel team rocks!!!";
		//We initialize the key pair for Alice and Bob
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair alice = keyPairGenerator.generateKeyPair();
		KeyPair bob = keyPairGenerator.generateKeyPair();

		//Encrypt text using Bob's public key
		final String cipherName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
		Cipher cipher = Cipher.getInstance(cipherName);
		cipher.init(Cipher.ENCRYPT_MODE, bob.getPublic());
		final byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);
		byte[] cipherTextBytes = cipher.doFinal(originalBytes);

		//Sign the original data using Alice's private key and get the signature bytes
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(alice.getPrivate());
		signature.update(originalBytes);
		byte[] signatureBytes = signature.sign();

		// Decrypt using bob's private key
		cipher.init(Cipher.DECRYPT_MODE, bob.getPrivate());
		byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
		String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

		log.info("Original:\t" + original);
		log.info("Encrypted:\t" + Util.convertByteToHexForNicePrinting(cipherTextBytes));
		log.info("Decrypted:\t" + decryptedString);
		if(!decryptedString.equals(original)){
			throw new IllegalArgumentException("Encrypted and decrypted text do not match");
		}

		//For verification
		//Initialize the signature using alice public key
		//Update the signature using decrypted data
		//verify the signature using Alice's signature bytes.
		log.info("Checking signature...");
		signature.initVerify(alice.getPublic());
		signature.update(decryptedBytes);
		final boolean signatureValid = signature.verify(signatureBytes);
		if(signatureValid){
			log.info("Yes, Alice wrote this.");
		} else {
			throw new IllegalArgumentException("Signature does not match");
		}
	}
}
