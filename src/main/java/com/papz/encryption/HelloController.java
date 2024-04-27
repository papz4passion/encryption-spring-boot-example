package com.papz.encryption;

import org.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.papz.encryption.core.AESEncryptionService;
import com.papz.encryption.core.RSAEncryptionService;
import com.papz.encryption.core.RSAManagement;

@RestController
public class HelloController {
    
	@GetMapping("/")
	public String index() {
		return "Greetings from Spring Boot!";
	}
	
	@GetMapping("/publicKey")
	public String getPublicKey() {
		return RSAManagement.getInstance().getPublicKeyString();
	}
	
	@PostMapping("/decrypt")
	public String decrypt(@RequestBody String cipherText) {
		return RSAEncryptionService.getInstance().decrypt(cipherText);
	}
	
	@PostMapping("/encrypt")
	public String encrypt(@RequestBody String plainText) {
		return RSAEncryptionService.getInstance().encrypt(plainText);
	}
	
	@PostMapping("/decryptWithSymmKey")
	public String decryptWithSymmKey(@RequestBody String reqBody) {
		return AESEncryptionService.getInstance().decrypt(reqBody);
	}
}
