package com.acmeledger.payout;

import java.io.InputStream;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;

/** Loads the payout window definitions shipped alongside the scheduler. */
public final class ScheduleLoader {

    private final Yaml yaml = new Yaml();

    public Map<String, Object> load(InputStream source) {
        return yaml.load(source);
    }
}
