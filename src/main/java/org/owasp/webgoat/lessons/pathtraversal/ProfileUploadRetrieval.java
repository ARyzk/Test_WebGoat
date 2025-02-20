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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
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
  private final Path catPicturesDirectory;
  private final Map<String, String> fileIdMapping = new HashMap<>();
  private final String secretFileName = "path-traversal-secret.jpg";

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    this.catPicturesDirectory = Paths.get(webGoatHomeDirectory, "PathTraversal", "cats").toAbsolutePath().normalize();
    try {
      Files.createDirectories(this.catPicturesDirectory);
    } catch (IOException e) {
      log.error("Failed to create cat pictures directory", e);
    }
  }

  @PostConstruct
  public void initAssignment() {
    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        String uuid = UUID.randomUUID().toString();
        Path targetFile = catPicturesDirectory.resolve(uuid + ".jpg").normalize();
        // Ensure the target file is within the allowed directory
        if (!targetFile.startsWith(catPicturesDirectory)) {
          log.error("Attempted path traversal during init: {}", targetFile);
          continue;
        }
        FileCopyUtils.copy(is, new FileOutputStream(targetFile.toFile()));
        fileIdMapping.put(String.valueOf(i), uuid);
      } catch (Exception e) {
        log.error("Unable to copy pictures", e);
      }
    }
    try {
      Path secretDirectory = catPicturesDirectory.getParent().getParent();
      Path secretFile = secretDirectory.resolve(secretFileName).normalize();
      
      // Security check: Ensure the secret file is created in the expected location
      if (!secretFile.startsWith(secretDirectory)) {
          log.error("Invalid secret file location detected during init");
          return;
      }
      
      Files.writeString(
          secretFile,
          "You found it submit the SHA-512 hash of your username as answer");
    } catch (IOException e) {
      log.error("Unable to write secret file", e);
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
      String fileId;
      
      if (id == null) {
        // For random picture requests, use a number between 1-10 to get the UUID
        fileId = fileIdMapping.get(String.valueOf(RandomUtils.nextInt(1, 11)));
      } else {
        // For specific requests, first check if it's a direct number mapping
        fileId = fileIdMapping.get(id);
        if (fileId == null) {
          // If not found in mapping, treat the id as a UUID
          fileId = id;
        }
      }

      // Construct and validate the file path
      Path requestedFile = catPicturesDirectory.resolve(fileId + ".jpg").normalize();
      
      // Security check: Ensure the resolved path is within the allowed directory
      if (!requestedFile.startsWith(catPicturesDirectory)) {
        log.warn("Attempted path traversal attack detected: {}", id);
        return ResponseEntity.notFound().build();
      }

      // Check if file exists and handle appropriately
      if (Files.exists(requestedFile)) {
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
            .body(FileCopyUtils.copyToByteArray(requestedFile.toFile()));
      }

      // Special case for the secret file - only return if explicitly requested and properly mapped
      if (fileId != null && fileId.toLowerCase().contains(secretFileName.toLowerCase())) {
        Path secretFile = catPicturesDirectory.getParent().getParent().resolve(secretFileName).normalize();
        // Additional security check for secret file
        if (!secretFile.startsWith(catPicturesDirectory.getParent().getParent())) {
          log.warn("Attempted path traversal to unauthorized location: {}", secretFile);
          return ResponseEntity.notFound().build();
        }
        if (Files.exists(secretFile)) {
          return ResponseEntity.ok()
              .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
              .body(FileCopyUtils.copyToByteArray(secretFile.toFile()));
        }
      }
      
      return ResponseEntity.notFound().build();
    } catch (Exception e) {
      log.warn("Error processing picture request: {}", e.getMessage());
      return ResponseEntity.notFound().build();
    }
              StringUtils.arrayToCommaDelimitedString(catPicture.getParentFile().listFiles())
                  .getBytes());
    } catch (IOException | URISyntaxException e) {
      log.error("Image not found", e);
    }

    return ResponseEntity.badRequest().build();
  }
}
