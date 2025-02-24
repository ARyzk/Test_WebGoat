/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"crypto-hashing.hints.1", "crypto-hashing.hints.2"})
public class HashingAssignment implements AssignmentEndpoint {
  public static final String[] SECRETS = {"secret", "admin", "password", "123456", "passw0rd"};
  private static final int ITERATIONS = 10000;
  private static final int KEY_LENGTH = 256;
  private static final int SALT_LENGTH = 16;
  private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

  private String generateSecureHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[SALT_LENGTH];
    random.nextBytes(salt);

    byte[] hash = pbkdf2(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);

    // Format: iterations:base64(salt):base64(hash)
    return ITERATIONS + ":" + Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
  }

  private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
    try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
      return skf.generateSecret(spec).getEncoded();
    } finally {
      spec.clearPassword();
    }
  }

  private boolean verifyPassword(String password, String storedHash) throws NoSuchAlgorithmException, InvalidKeySpecException {
    String[] parts = storedHash.split(":");
    int iterations = Integer.parseInt(parts[0]);
    byte[] salt = Base64.getDecoder().decode(parts[1]);
    byte[] hash = Base64.getDecoder().decode(parts[2]);

    char[] passwordChars = password.toCharArray();
    try {
      byte[] testHash = pbkdf2(passwordChars, salt, iterations, hash.length * 8);
      return MessageDigest.isEqual(hash, testHash);
    } finally {
      // Clear sensitive data
      for(int i = 0; i < passwordChars.length; i++) {
        passwordChars[i] = 0;
      }
    }
  }

  @RequestMapping(path = "/crypto/hashing/md5", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getMd5(HttpServletRequest request) {
    try {
      String md5Hash = (String) request.getSession().getAttribute("md5Hash");
      if (md5Hash == null) {
        String secret = SECRETS[new SecureRandom().nextInt(SECRETS.length)];
        
        // Generate secure hash instead of MD5
        md5Hash = generateSecureHash(secret);
        request.getSession().setAttribute("md5Hash", md5Hash);
        request.getSession().setAttribute("md5Secret", secret);
      }
      return md5Hash;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException("Error generating secure hash", e);
    }
  }

  @RequestMapping(path = "/crypto/hashing/sha256", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSha256(HttpServletRequest request) {
    try {
      String sha256 = (String) request.getSession().getAttribute("sha256Hash");
      if (sha256 == null) {
        String secret = SECRETS[new SecureRandom().nextInt(SECRETS.length)];
        
        // Generate secure hash instead of SHA-256
        sha256 = generateSecureHash(secret);
        request.getSession().setAttribute("sha256Hash", sha256);
        request.getSession().setAttribute("sha256Secret", secret);
      }
      return sha256;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException("Error generating secure hash", e);
    }
  }

  @PostMapping("/crypto/hashing")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_pwd1,
      @RequestParam String answer_pwd2) {
    try {
      String md5Secret = (String) request.getSession().getAttribute("md5Secret");
      String sha256Secret = (String) request.getSession().getAttribute("sha256Secret");
      String md5Hash = (String) request.getSession().getAttribute("md5Hash");
      String sha256Hash = (String) request.getSession().getAttribute("sha256Hash");

      if (answer_pwd1 != null && answer_pwd2 != null) {
        // For learning purposes, we still compare with the original secrets
        // In a real application, we would only store and verify the hashes
        if (answer_pwd1.equals(md5Secret) && answer_pwd2.equals(sha256Secret)) {
          // Demonstrate that verification works with the secure hashes
          boolean validHash1 = verifyPassword(answer_pwd1, md5Hash);
          boolean validHash2 = verifyPassword(answer_pwd2, sha256Hash);
          if (validHash1 && validHash2) {
            return success(this).feedback("crypto-hashing.success").build();
          }
        } else if (answer_pwd1.equals(md5Secret) || answer_pwd2.equals(sha256Secret)) {
          return failed(this).feedback("crypto-hashing.oneok").build();
        }
      }
      return failed(this).feedback("crypto-hashing.empty").build();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException("Error verifying password", e);
    }
  }
}
