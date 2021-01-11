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

@Slf4j
public class AsymmetricBasicDemo {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, SignatureException {
		final String original = "Tuzel team rocks!!!";

		//Generate key pair for the BOB
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();

		//Initialize the cipher with encryption mode
		final String cipherName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
		Cipher cipher = Cipher.getInstance(cipherName);
		cipher.init(Cipher.ENCRYPT_MODE, aliceKeyPair.getPublic());

		//Here Alice is writing to herself
		final byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);
		byte[] cipherTextBytes = cipher.doFinal(originalBytes);

		//This is important. Some one encrypted the message but who encrypted that message.
		//We sign the original bytes with the signer initialized with alice private key.
		//So we can mathematically prove the original bytes is encrypted by Alice
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(aliceKeyPair.getPrivate());
		sig.update(originalBytes);
		byte[] signatureBytes = sig.sign();

		// Decrypt the data using Alice's private key
		cipher.init(Cipher.DECRYPT_MODE, aliceKeyPair.getPrivate());
		byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
		String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

		log.info("Original:\t" + original);
		log.info("Encrypted:\t" + Util.convertByteToHexForNicePrinting(cipherTextBytes));
		log.info("Decrypted:\t" + decryptedString);
		if(!decryptedString.equals(original)){
			throw new IllegalArgumentException("Encrypted and decrypted text do not match");
		}

		log.info("Checking the signature...");
		sig.initVerify(aliceKeyPair.getPublic());
		sig.update(decryptedBytes); //We update the signature using decryptedBytes
		final boolean signatureValid = sig.verify(signatureBytes);
		if(signatureValid){
			log.info("Signature is valid.");
		} else {
			throw new IllegalArgumentException("Signature is not valid and does not match");
		}
	}
}
