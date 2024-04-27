/**
 * 
 */
package com.papz.encryption.core;

import java.util.Arrays;
import java.util.Base64;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

import com.fasterxml.jackson.databind.util.JSONPObject;

import java.security.SecureRandom;

import java.nio.*;
import java.nio.charset.StandardCharsets;

/**
 * 
 */
public final class AESEncryptionService {
	
	private static AESEncryptionService instance;
	private AESEncryptionService() {}
	
	private static final int GCM_IV_LENGTH = 12;
	private static final int GCM_TAG_LENGTH = 16;
	private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
	private static final String INVALID_KEY_ERROR = "Invalid AES key length";
	
	public static AESEncryptionService getInstance() {
		if(instance == null) {
			instance = new AESEncryptionService();
		}
		
		return instance;
	}
	
	public String encrypt(String plainText, String key) {
		try {
			byte[] keyBytes = Base64.getDecoder().decode(key);
			if(keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
				throw new IllegalArgumentException(INVALID_KEY_ERROR);
			}
			
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
			SecureRandom secureRandom = new SecureRandom();
			byte[] iv = new byte[GCM_IV_LENGTH];
			secureRandom.nextBytes(iv);
			
			Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
			GCMParameterSpec paramterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramterSpec);
			
			byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			byte[] tag = Arrays.copyOfRange(cipherText, cipherText.length - GCM_TAG_LENGTH, cipherText.length);
			byte[] cipherTextWithoutTag = Arrays.copyOf(cipherText, cipherText.length);
			
			return "{"
					+ "\"iv\":\"" + byteArrayToHexString(iv) + "\","
					+ "\"encrypted\":\"" + byteArrayToHexString(cipherTextWithoutTag) + "\","
					+ "\"tag\":\"" + byteArrayToHexString(tag) + "\""
					+ "}";
		
		} catch (Exception e) {
			return plainText;
		}
	}
	
	public String decrypt(String encryptedText) {
		try {
			JSONObject jsonInput = new JSONObject(encryptedText);
			String base64Tag = jsonInput.getString("tag");
			String base64Iv = jsonInput.getString("iv");
			String base64CipherText = jsonInput.getString("encrypted");
			String symmKey = jsonInput.getString("symmKey");
			
			byte[] keyBytes = Base64.getDecoder().decode(symmKey);
			byte[] cipherText = Base64.getDecoder().decode(base64CipherText);
			byte[] iv = Base64.getDecoder().decode(base64Iv);
			byte[] tag = Base64.getDecoder().decode(base64Tag);
			
			if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
				throw new IllegalArgumentException(INVALID_KEY_ERROR);
			}
			
			SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
			GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
			Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
			
			byte[] cipherWithTag = ByteBuffer.allocate(cipherText.length + tag.length)
					.put(cipherText)
					.put(tag)
					.array();
			byte[] decryptedBytes = cipher.doFinal(cipherWithTag);
			
			String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
			System.out.println(decryptedText);
			return decryptedText;
			
		} catch (Exception e) {
			e.printStackTrace();
			return encryptedText;	
		}
	}
	
	private String byteArrayToHexString(byte[] bytes) {
		StringBuilder hexString = new StringBuilder();
		for (byte b: bytes) {
			String hexByte = Integer.toHexString(b);
			if (hexByte.length() == 1) {
				hexString.append('0');
			}
			hexString.append(hexByte);
		}
		return hexString.toString();
	}
}
