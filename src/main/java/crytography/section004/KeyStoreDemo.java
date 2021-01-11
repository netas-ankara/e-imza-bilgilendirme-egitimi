package crytography.section004;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Slf4j
public class KeyStoreDemo {

	public static void main(String[] args) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, OperatorCreationException {
		//Crete the keystore file
		String keystoreFileLocation = System.getProperty("user.home") + "/Desktop/keystore.jks";
		final File keystoreFile = new File(keystoreFileLocation);
		if(keystoreFile.createNewFile()){
			log.info("Key store file is created");
		} else {
			log.info("Key store file already exists");
		}

		// Crete the keystore
		final KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, "SomePass".toCharArray());

		// Generate a key pair
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();

		//Wrap the key pair in a certificate using Bouncy Castle
		final Certificate wrappedCertificate = generateCertificate(keyPair);
		Entry entry = new PrivateKeyEntry(keyPair.getPrivate(), new Certificate[]{wrappedCertificate});

		//Store the password protected private entry on the keystore
		keyStore.setEntry("tuzel", entry, new KeyStore.PasswordProtection("SomePass".toCharArray()));
		keyStore.store(new FileOutputStream(keystoreFile), "SomePass".toCharArray());

		log.info("Password protected private entry is successfully stored on the keystore.");
	}

	/**
	 * Store keystore pair in a certificate
	 *
	 * @param keyPair A KeyPair to wrap
	 * @return A wrapped certificate with constant name
	 * @throws CertificateException      JcaX509CertificateConverter
	 * @throws OperatorCreationException JcaContentSignerBuilder
	 */
	public static Certificate generateCertificate(KeyPair keyPair) throws CertificateException, OperatorCreationException {
		X500Name name = new X500Name("cn=Tuzel");
		SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		final Date start = new Date();
		final Date until = Date.from(LocalDate.now().plus(365, ChronoUnit.DAYS).atStartOfDay().toInstant(ZoneOffset.UTC));
		final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name, new BigInteger(10, new SecureRandom()), //Choose something better for real use
				start, until, name, subPubKeyInfo);
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider()).build(keyPair.getPrivate());
		final X509CertificateHolder holder = builder.build(signer);

		return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
	}
}
