package org.tauf.docker.domain;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface Certificate {
    PrivateKey getPrivateKey();
    X509Certificate getCertificate();
    DomainCertificate getCa();
}
