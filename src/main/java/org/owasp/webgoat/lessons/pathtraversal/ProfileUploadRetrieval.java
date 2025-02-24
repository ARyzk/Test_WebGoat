/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "path-traversal-profile-retrieve.hint1",
  "path-traversal-profile-retrieve.hint2",
  "path-traversal-profile-retrieve.hint3",
  "path-traversal-profile-retrieve.hint4",
  "path-traversal-profile-retrieve.hint5",
  "path-traversal-profile-retrieve.hint6"
})
@Slf4j
public class ProfileUploadRetrieval implements AssignmentEndpoint {
  private final File catPicturesDirectory;

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    this.catPicturesDirectory = new File(webGoatHomeDirectory, "/PathTraversal/" + "/cats");
    this.catPicturesDirectory.mkdirs();
  }

  @PostConstruct
  public void initAssignment() {
    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        FileCopyUtils.copy(is, new FileOutputStream(new File(catPicturesDirectory, i + ".jpg")));
      } catch (Exception e) {
        log.error("Unable to copy pictures" + e.getMessage());
      }
    }
    var secretDirectory = this.catPicturesDirectory.getParentFile().getParentFile();
    try {
      Files.writeString(
          secretDirectory.toPath().resolve("path-traversal-secret.jpg"),
          "You found it submit the SHA-512 hash of your username as answer");
    } catch (IOException e) {
      log.error("Unable to write secret in: {}", secretDirectory, e);
    }
  }

  @PostMapping("/PathTraversal/random")
  @ResponseBody
  public AttackResult execute(
      @RequestParam(value = "secret", required = false) String secret,
      @CurrentUsername String username) {
    if (Sha512DigestUtils.shaHex(username).equalsIgnoreCase(secret)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    try {
      var id = request.getParameter("id");
      if (id == null) {
        id = String.valueOf(RandomUtils.nextInt(1, 11));
      }
      
      // Validate the id parameter (only allow alphanumeric and limited special chars)
      if (!id.matches("^[a-zA-Z0-9-_]+$")) {
        log.warn("Invalid characters in file name request: {}", id);
        return ResponseEntity.badRequest().body("Invalid file name");
      }
      
      // Add input length validation
      if (id.length() > 50) {
        log.warn("File name too long: {}", id);
        return ResponseEntity.badRequest().body("Invalid file name");
      }
      
      java.nio.file.Path basePath = catPicturesDirectory.toPath().normalize();
      java.nio.file.Path requestedPath = basePath.resolve(id + ".jpg").normalize();
      
      // Verify the resolved path is within the allowed directory
      if (!requestedPath.startsWith(basePath)) {
        log.warn("Path traversal attempt detected: {}", requestedPath);
        return ResponseEntity.badRequest().body("Invalid file path");
      }
      
      File catPicture = requestedPath.toFile();
      
      // Verify file exists and check MIME type
      if (catPicture.exists()) {
        String mimeType = Files.probeContentType(requestedPath);
        if (mimeType == null || !mimeType.equals(MediaType.IMAGE_JPEG_VALUE)) {
          log.warn("Invalid file type detected for file: {}", id);
          return ResponseEntity.badRequest().body("Invalid file type");
        }
        
        return ResponseEntity.ok()
            .contentType(MediaType.IMAGE_JPEG)
            .location(new URI("/PathTraversal/random-picture?id=" + id))
            .body(Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(catPicture)));
      }
      
      // Return generic 404 without revealing directory contents
      return ResponseEntity.notFound().build();
      
    } catch (IOException | URISyntaxException e) {
      // Log the error but return generic message
      log.error("Error processing file request for id: {}", request.getParameter("id"), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body("An error occurred processing your request");
    }
  }
}
