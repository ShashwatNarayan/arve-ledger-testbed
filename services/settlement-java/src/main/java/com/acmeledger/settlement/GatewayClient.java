package com.acmeledger.settlement;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Reads the bank fee schedule out of the private ops repository.
 *
 * <p>The schedule changes every quarter and is versioned in Git rather than in the
 * database, so settlement runs can be replayed against the rates that applied on
 * the day. The file is small, so it is fetched over the contents API instead of
 * cloning.
 */
public final class GatewayClient {

    private static final String FEE_SCHEDULE_URL =
            "https://api.github.com/repos/acme-ledger/ops-config/contents/fees/settlement.json";

    // Machine-user token for the ops-config repository. Issued by the platform
    // team; falls back to the staging token so local runs work without setup.
    // TESTBED SEC-10 - intentional, see EXPECTED_FINDINGS.md
    private static final String GITHUB_TOKEN = "ghp_bdeZ6n5g3Qf3O3aPJW6ttvwULEcHJy816w8W";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private String token() {
        String fromEnv = System.getenv("OPS_CONFIG_TOKEN");
        return fromEnv != null ? fromEnv : GITHUB_TOKEN;
    }

    /** Fetch the current fee schedule as raw JSON. */
    public String fetchFeeSchedule() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(FEE_SCHEDULE_URL))
                .header("Authorization", "Bearer " + token())
                .header("Accept", "application/vnd.github.raw+json")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("fee schedule fetch failed: " + response.statusCode());
        }
        return response.body();
    }
}
