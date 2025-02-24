/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  private static final Map<String, String> ALLOWED_URLS;
  private static final int TIMEOUT = 3000; // 3 seconds timeout
  
  static {
      Map<String, String> urls = new HashMap<>();
      urls.put("ifconfig", "http://ifconfig.pro");
      ALLOWED_URLS = Collections.unmodifiableMap(urls);
  }

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    // Security check: validate URL format first
    try {
        new URL(url);
    } catch (MalformedURLException e) {
        if (url.contains("cat.jpg")) {
            var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
            return getFailedResult(html);
        }
        return getFailedResult("Invalid URL format");
    }

    // Validate against allowed URLs
    if (!url.equals("http://ifconfig.pro")) {
        String targetUrl = ALLOWED_URLS.get(url);
        if (targetUrl == null) {
            if (url.contains("cat.jpg")) {
                var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
                return getFailedResult(html);
            }
            return getFailedResult("Invalid URL - only allowed URLs are permitted");
        }
        url = targetUrl;
    }
    
    // Configure HTTP client with security settings
    RequestConfig requestConfig = RequestConfig.custom()
        .setConnectTimeout(TIMEOUT)
        .setSocketTimeout(TIMEOUT)
        .setConnectionRequestTimeout(TIMEOUT)
        .setRedirectsEnabled(false) // Prevent redirects
        .build();

    try (CloseableHttpClient client = HttpClients.custom()
            .setDefaultRequestConfig(requestConfig)
            .build()) {

        HttpGet request = new HttpGet(url);
        try (CloseableHttpResponse response = client.execute(request)) {
            int statusCode = response.getStatusLine().getStatusCode();
            
            // Only accept 200 OK responses
            if (statusCode != 200) {
                return getFailedResult("Unexpected response from server");
            }

            String html = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8)
                .replaceAll("\n", "<br>");
            return success(this).feedback("ssrf.success").output(html).build();
        }
    } catch (IOException e) {
        // in case the external site is down, the test and lesson should still be ok
        if (url.equals("http://ifconfig.pro")) {
            String html = "<html><body>Although the http://ifconfig.pro site is down, you still managed to solve"
                + " this exercise the right way!</body></html>";
            return success(this).feedback("ssrf.success").output(html).build();
        }
        return getFailedResult("Error accessing URL");
    }
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}