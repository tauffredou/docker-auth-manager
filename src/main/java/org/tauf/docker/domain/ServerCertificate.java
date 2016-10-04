package org.tauf.docker.domain;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class ServerCertificate implements Certificate{
    private String name;
    private PrivateKey privateKey;
    private X509Certificate certificate;

    private DomainCertificate ca;

    public ServerCertificate() {
    }

    public ServerCertificate(String name, PrivateKey privateKey, X509Certificate certificate,DomainCertificate ca) {
        this.name = name;
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.ca = ca;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public DomainCertificate getCa() {
        return ca;
    }

    public void setCa(DomainCertificate ca) {
        this.ca = ca;
    }
}
