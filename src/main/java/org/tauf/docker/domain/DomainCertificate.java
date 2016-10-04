package org.tauf.docker.domain;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Entity
public class DomainCertificate {
    @Id
    private String name;

    private PrivateKey privateKey;
    private X509Certificate certificate;

    public DomainCertificate() {
    }

    public DomainCertificate(String domain, PrivateKey rootPrivateKey, X509Certificate certificate) {

        this.name = domain;
        this.privateKey = rootPrivateKey;
        this.certificate = certificate;
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


}
