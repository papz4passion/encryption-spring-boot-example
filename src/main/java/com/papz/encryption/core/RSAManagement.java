package com.papz.encryption.core;

import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

public class RSAManagement {
	
	private static RSAManagement instance;
	private RSAManagement() {}
	
	public static RSAManagement getInstance() {
		if(instance == null) {
			instance = new RSAManagement();
			instance.generateKeyPair();
		}
		return instance;
	}
	
	private SecureRandom random = new SecureRandom();
	private KeyPairGenerator keyPairGenerator = null;
	private Key publicKey = null;
	
	private Key privateKey = null;
	private long timeKeyGenerated = 0;
	private boolean flag = true;
	
	public Key getPublicKey() {
		return publicKey;
	}

	public Key getPrivateKey() {
		return privateKey;
	}

	public void generateKeyPair() {
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048, random);
			
		} catch(Exception e) {
			System.out.println(e.getStackTrace());
		}
		
		KeyPair pair = keyPairGenerator.generateKeyPair();
		publicKey = pair.getPublic();
		privateKey = pair.getPrivate();
		timeKeyGenerated = new Date().getTime();
	}

	public String getPublicKeyString() {
		if(publicKey == null) {
			generateKeyPair();
		}
		return Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}
}
