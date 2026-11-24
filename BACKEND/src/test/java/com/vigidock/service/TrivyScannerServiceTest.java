package com.vigidock.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TrivyScannerServiceTest {
    private final TrivyScannerService scanner = new TrivyScannerService(new ObjectMapper());

    @Test void acceptsArtifactRegistryTagAndDigest() {
        assertDoesNotThrow(() -> scanner.validateImageName("asia-south1-docker.pkg.dev/project/repo/image:tag"));
        assertDoesNotThrow(() -> scanner.validateImageName("asia-south1-docker.pkg.dev/project/repo/image@sha256:" + "a".repeat(64)));
    }

    @Test void rejectsShellMetacharactersAndMalformedArtifactRegistryHost() {
        assertThrows(IllegalArgumentException.class, () -> scanner.validateImageName("asia-south1-docker.pkg.dev/p/r/i:tag;id"));
        assertThrows(IllegalArgumentException.class, () -> scanner.validateImageName("asia-south1-docker.pkg.dev/p/r/i:tag`id`"));
        assertThrows(IllegalArgumentException.class, () -> scanner.validateImageName("bad!host-docker.pkg.dev/p/r/i:tag"));
    }
}
