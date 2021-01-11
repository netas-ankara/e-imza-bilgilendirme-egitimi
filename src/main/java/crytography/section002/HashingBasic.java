package crytography.section002;

import crytography.Util;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class HashingBasic {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		try(InputStream in = HashingBasic.class.getClassLoader().getResourceAsStream("simple_text_file.txt")){
			final byte[] bytes = new byte[1024];
			assert in != null;
			int length = in.read(bytes);
			while(length != -1){
				md.update(bytes, 0, length);
				length = in.read(bytes);
			}
		} catch (IOException e){
			log.error(e.getMessage(), e);
		}

		final byte[] hashed = md.digest();
		log.info("The final message digest with SHA-256:{}", Util.convertByteToHexForNicePrinting(hashed));
	}
}
