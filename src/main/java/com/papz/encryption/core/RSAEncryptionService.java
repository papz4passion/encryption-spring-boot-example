package com.papz.encryption.core;

import java.nio.charset.StandardCharsets;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import com.papz.encryption.core.RSAManagement;

public class RSAEncryptionService {

	private static RSAEncryptionService instance;
	private final String RSA_ALGORITHM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
	private final String HASHING_ALGORITHM = "SHA-256";
	
	private RSAEncryptionService() {}
	
	public static RSAEncryptionService getInstance() {
		if(instance == null) {
			instance = new RSAEncryptionService();
		}
		
		return instance;
 	}
	
	public String encrypt(String content) {
		try {
			byte[] contentBytes = content.getBytes();
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			OAEPParameterSpec oaepParams = new OAEPParameterSpec(HASHING_ALGORITHM, 
					"MGF1", new MGF1ParameterSpec(HASHING_ALGORITHM), PSource.PSpecified.DEFAULT);
			
			RSAManagement.getInstance().generateKeyPair();
			cipher.init(Cipher.ENCRYPT_MODE, RSAManagement.getInstance().getPublicKey(), oaepParams);
			byte [] cipherContent = cipher.doFinal(contentBytes);
			
			return Base64.getEncoder().encodeToString(cipherContent);
		} catch(Exception e) {
			System.out.println(e.getMessage());
			return content;
		}
		
	}
	
	public String decrypt(String cipherContent) {
		
		try {
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			OAEPParameterSpec oaepParams = new OAEPParameterSpec(HASHING_ALGORITHM, "MGF1", new MGF1ParameterSpec(HASHING_ALGORITHM), PSource.PSpecified.DEFAULT);
			cipher.init(Cipher.DECRYPT_MODE, RSAManagement.getInstance().getPrivateKey(), oaepParams);
			
			byte[] cipherContentBytes = Base64.getDecoder().decode(cipherContent.getBytes());
			byte[] decryptedContent = cipher.doFinal(cipherContentBytes);
			String result = new String(decryptedContent, StandardCharsets.UTF_8);
			
			System.out.println("decryptedText: " + result);
			return result;
			
		} catch (Exception e) {
			return cipherContent;
		}
	}
}
