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
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Random;
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
  // Secure password hashing parameters as per OWASP recommendations
  private static final int PBKDF2_ITERATIONS = 310000; // High iteration count for PBKDF2
  private static final int HASH_KEY_LENGTH = 256; // 256-bit key length
  private static final int SALT_LENGTH = 16; // 16 bytes = 128 bits of salt
  private static final String SECURE_HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  
  // Example secrets for the assignment - in real apps, never store passwords in code
  private static final String[] SECRETS = {"secret", "admin", "password", "123456", "passw0rd"};

  /**
   * Securely hashes a password using PBKDF2 with SHA-256.
   * 
   * @param password The password to hash
   * @return A string in the format "iterations:base64(salt):base64(hash)"
   * @throws NoSuchAlgorithmException If the PBKDF2 algorithm is not available
   * @throws InvalidKeySpecException If there's an issue with the key specification
   * @throws IllegalArgumentException If the password is null or empty
   */
  private String hashPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
      if (password == null || password.isEmpty()) {
          throw new IllegalArgumentException("Password cannot be null or empty");
      }

      byte[] salt = new byte[SALT_LENGTH];
      SECURE_RANDOM.nextBytes(salt);
      
      KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, HASH_KEY_LENGTH);
      SecretKeyFactory factory = SecretKeyFactory.getInstance(SECURE_HASH_ALGORITHM);
      
      byte[] hash = factory.generateSecret(spec).getEncoded();
      return PBKDF2_ITERATIONS + ":" + Base64.getEncoder().encodeToString(salt) + ":" + 
             Base64.getEncoder().encodeToString(hash);
  }

  /**
   * Verifies a password against a stored hash using PBKDF2.
   * 
   * @param password The password to verify
   * @param storedHash The stored hash in the format "iterations:base64(salt):base64(hash)"
   * @return true if the password matches, false otherwise
   * @throws NoSuchAlgorithmException If the PBKDF2 algorithm is not available
   * @throws InvalidKeySpecException If there's an issue with the key specification
   * @throws IllegalArgumentException If any input is invalid
   */
  private boolean verifyPassword(String password, String storedHash) 
          throws NoSuchAlgorithmException, InvalidKeySpecException {
      if (password == null || password.isEmpty() || storedHash == null || storedHash.isEmpty()) {
          throw new IllegalArgumentException("Password and stored hash cannot be null or empty");
      }

      String[] parts = storedHash.split(":");
      if (parts.length != 3) {
          throw new IllegalArgumentException("Invalid stored hash format");
      }

      try {
          int iterations = Integer.parseInt(parts[0]);
          byte[] salt = Base64.getDecoder().decode(parts[1]);
          byte[] hash = Base64.getDecoder().decode(parts[2]);

          KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, hash.length * 8);
          SecretKeyFactory factory = SecretKeyFactory.getInstance(SECURE_HASH_ALGORITHM);
          byte[] testHash = factory.generateSecret(spec).getEncoded();

          return MessageDigest.isEqual(hash, testHash); // Constant-time comparison
      } catch (IllegalArgumentException e) {
          throw new IllegalArgumentException("Invalid hash format: " + e.getMessage());
      }
  }

  /**
   * Creates or retrieves a securely hashed password.
   * This endpoint replaces the old MD5 hashing endpoint with secure PBKDF2 hashing.
   */
  @RequestMapping(path = "/crypto/hashing/md5", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSecureHash(HttpServletRequest request) {
    try {
        String hashedPassword = (String) request.getSession().getAttribute("hashedPassword");
        if (hashedPassword == null) {
            // Use SecureRandom instead of Random for cryptographic operations
            String secret = SECRETS[SECURE_RANDOM.nextInt(SECRETS.length)];
            hashedPassword = hashPassword(secret);
            request.getSession().setAttribute("hashedPassword", hashedPassword);
            request.getSession().setAttribute("passwordSecret", secret);
        }
        return hashedPassword;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        throw new RuntimeException("Error generating secure hash", e);
    }
  }

  /**
   * Returns the same secure hash as getSecureHash().
   * This maintains compatibility while using secure PBKDF2 hashing instead of SHA-256.
   */
  @RequestMapping(path = "/crypto/hashing/sha256", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSha256(HttpServletRequest request) {
    return getSecureHash(request); // Reuse the same secure hashing mechanism
  }

  /**
   * Validates the user's password guesses against the stored secret.
   */
  @PostMapping("/crypto/hashing")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam(required = false) String answer_pwd1,
      @RequestParam(required = false) String answer_pwd2) {

    try {
        // Input validation
        if (answer_pwd1 == null || answer_pwd2 == null || answer_pwd1.isEmpty() || answer_pwd2.isEmpty()) {
            return failed(this).feedback("crypto-hashing.empty").build();
        }

        String storedHash = (String) request.getSession().getAttribute("hashedPassword");
        String originalSecret = (String) request.getSession().getAttribute("passwordSecret");

        // Verify both answers match the original secret
        // Note: In a real application, we would use verifyPassword() instead of direct string comparison
        boolean answer1Correct = answer_pwd1.equals(originalSecret);
        boolean answer2Correct = answer_pwd2.equals(originalSecret);

        if (answer1Correct && answer2Correct) {
            return success(this).feedback("crypto-hashing.success").build();
        } else if (answer1Correct || answer2Correct) {
            return failed(this).feedback("crypto-hashing.oneok").build();
        }

        return failed(this).feedback("crypto-hashing.invalid").build();
    } catch (Exception e) {
        return failed(this).feedback("crypto-hashing.error").build();
    }
  }
}
