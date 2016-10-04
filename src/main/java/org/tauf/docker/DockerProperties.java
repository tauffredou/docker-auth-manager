package org.tauf.docker;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "app")
@Component
public class DockerProperties {
    private int tokenValidity;

    public int getTokenValidity() {
        return tokenValidity;
    }

    public void setTokenValidity(int tokenValidity) {
        this.tokenValidity = tokenValidity;
    }
}
