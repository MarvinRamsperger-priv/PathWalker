# PathWalker LFI Scanner

PathWalker is a Burp Suite Montoya extension for finding Local File Inclusion (LFI) and path traversal issues from URLs already discovered in Burp.

## Description

PathWalker automates sitemap-driven LFI and path traversal testing. It walks each directory level of discovered URL paths and injects traversal payloads from every path context, rather than only testing the final endpoint. It also tests GET parameters with direct file and traversal payload variants.

To support authenticated testing, PathWalker can automatically load target URLs from Burp's sitemap and reuse session cookies and JWT Bearer tokens already observed in Burp Proxy history.

## Features

* **Directory-aware path walking:** Tests traversal payloads from each parent directory in a discovered URL path, such as `/a/b/c/`, `/a/b/`, and `/a/`. PathWalker tracks tested request/payload combinations during each scan run, so equivalent generated requests are de-duplicated instead of being sent repeatedly.
* **GET-parameter testing:** Replaces GET parameter values with direct file and traversal payload variants.
* **Payload generation:** Covers common Linux and Windows target files with URL-encoded, double-encoded, backslash, and non-standard traversal variants.
* **High-confidence detection:** Looks for known `/etc/passwd` and Windows `system.ini` signatures to reduce false positives.
* **Session assistance:** Loads recent cookies and JWT Bearer tokens for the selected host from Burp Proxy history. Values remain editable before scanning.
* **Burp integration:** Provides a dedicated Burp tab, loads target URLs from the sitemap, and registers confirmed findings as Burp sitemap issues.
* **Smart target selection:** Converts common static asset URLs, such as `.js`, `.css`, and `.png`, to their parent directories for more useful path testing.
* **Large-project safeguards:** Caps sitemap, proxy-history, loaded URL, scan target, response, and log processing.

## Usage

1. Browse the target application through Burp so the Target sitemap and Proxy history contain useful entries.
2. Open the **PathWalker** tab.
3. Click **Refresh Hosts** and select a host.
4. Click **Load URLs, Cookies/JWTs**.
5. Review the loaded URLs and session values. Remove anything you do not want to scan.
6. Click **Start Scan**.
7. Review hits in the PathWalker results table and in Burp's Target sitemap issues.

## Scope And Safety

PathWalker sends active traversal requests. Only scan systems you are authorized to test.

The scanner currently focuses on:

* HTTP and HTTPS URLs.
* GET requests.
* URL path walking and GET query parameters.
* Linux `/etc/passwd` and Windows `system.ini` style file disclosures.

It does not currently test POST bodies, JSON/XML parameters, multipart uploads, WebSockets, or arbitrary custom file lists.

## False Positives And Limitations

PathWalker only reports findings when response content matches high-confidence local file signatures. This keeps false positives low, but it can miss vulnerabilities that return different files, partial file contents, transformed content, or access-controlled responses.

For very large Burp projects, PathWalker uses caps when reading sitemap and proxy-history data. If a target host has more entries than the caps allow, load a narrower Burp project or remove unrelated sitemap/history entries before scanning.

## Build

```powershell
gradle jar
```
