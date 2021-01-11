package crytography.section006;

import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@Slf4j
public class CertificateChainDemo {

	public static void main(String[] args) throws IOException {
		URL url = new URL("https://giris.etuzel.gov.ct.tr/login.jsf");
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		conn.connect();
		Certificate[] certs = conn.getServerCertificates();

		Arrays.stream(certs).forEach(CertificateChainDemo::printCert);

		log.info("Finished iterating certificates --------------------------------------------");
		log.info("There are " + certs.length + " certificates.");
		Arrays.stream(certs).map(cert -> (X509Certificate) cert).forEach(x509 -> log.info(x509.getIssuerDN().getName()));
		log.info("The final certificate is for: " + conn.getPeerPrincipal());
	}

	private static void printCert(Certificate cert) {
		log.info("---------------------------------------------------------------------------");
		log.info("Certificate is: " + cert);
		if(cert instanceof X509Certificate){
			try{
				((X509Certificate) cert).checkValidity();
				log.info("Certificate is active for current date");
			} catch (CertificateExpiredException e){
				log.error("Certificate expired " + e.getMessage(), e);
			} catch (CertificateNotYetValidException e){
				log.error("Certificate is not valid " + e.getMessage(), e);
			}
		} else {
			log.error("Unexpected cert type.");
		}
	}
}
