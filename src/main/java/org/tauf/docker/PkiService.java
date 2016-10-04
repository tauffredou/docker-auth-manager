package org.tauf.docker;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.tauf.docker.domain.*;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import static java.security.Security.addProvider;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

@Service
public class PkiService {

    private final Logger LOGGER = LoggerFactory.getLogger(PkiService.class);

    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    private static final String KEY_GENERATION_ALGORITHM = "RSA";

    private static final int CA_KEYSIZE = 2048;
    @Autowired
    DomainCertificateRepository caCertificateRepository;
    @Autowired
    TokenRepository tokenRepository;
    @Autowired
    DockerProperties properties;

    static {
        addProvider(new BouncyCastleProvider());
    }

    public ServerCertificate createServerCertificate(String domain, String name) {
        DomainCertificate ca = getCACertificate(domain);

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM, PROVIDER_NAME);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            String issuer = "CN=" + name;
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new org.bouncycastle.asn1.x500.X500Name(ca.getCertificate().getIssuerX500Principal().getName()),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24),
                    new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365)),
                    new org.bouncycastle.asn1.x500.X500Name(issuer),
                    keyPair.getPublic());

            //            GeneralNames subjectAltName = new GeneralNames(
            //                    new GeneralName(GeneralName.rfc822Name, "testalt"));
            //
            //            builder.addExtension(Extension.subjectAlternativeName, false, new DEROctetString(subjectAltName));

            X509Certificate certificate = signCertificate(builder, ca.getPrivateKey());

            ServerCertificate serverCertificate = new ServerCertificate(name, keyPair.getPrivate(), certificate, ca);
            LOGGER.info("Create server certificate {}/{}", domain, name);
            return serverCertificate;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(signedWithPrivateKey);
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
    }

    public ClientCertificate createClientCertificate(String domain, String user, String role) throws Exception {
        DomainCertificate ca = getCACertificate(domain);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM, PROVIDER_NAME);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.SECOND, properties.getTokenValidity());
        Date notAfter = calendar.getTime();
        Token token = new Token(user, role, notAfter);
        String issuer = "CN=" + token.encode();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new org.bouncycastle.asn1.x500.X500Name(ca.getCertificate().getIssuerX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                new org.bouncycastle.asn1.x500.X500Name(issuer),
                keyPair.getPublic());

        X509Certificate certificate = signCertificate(builder, ca.getPrivateKey());

        ClientCertificate clientCertificate = new ClientCertificate(user, keyPair.getPrivate(), certificate, ca);
        tokenRepository.save(token);
        LOGGER.info("Create client certificate {}/{}", domain, user);
        return clientCertificate;

    }

    private String getRole(String domain, String user) {return "admin";}

    private DomainCertificate createCACertificate(String domain) {
        try {
            // Create the public/private rsa key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM, PROVIDER_NAME);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            String issuer = "CN=" + domain;
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new org.bouncycastle.asn1.x500.X500Name(issuer),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
                    new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30 * 365 * 10)),
                    new org.bouncycastle.asn1.x500.X500Name(issuer),
                    keyPair.getPublic());

            builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

            KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
            builder.addExtension(Extension.keyUsage, false, usage);

            ASN1EncodableVector purposes = new ASN1EncodableVector();
            purposes.add(KeyPurposeId.id_kp_serverAuth);
            purposes.add(KeyPurposeId.id_kp_clientAuth);
            purposes.add(KeyPurposeId.anyExtendedKeyUsage);
            builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

            X509Certificate rootCertificate = signCertificate(builder, keyPair.getPrivate());

            DomainCertificate domainCertificate = new DomainCertificate(domain, keyPair.getPrivate(), rootCertificate);
            caCertificateRepository.save(domainCertificate);
            LOGGER.info("CA certificate {} created", domain);
            return domainCertificate;
        } catch (Exception e) {
            LOGGER.error("Cannot generate CA certificate {}", domain, e);
            return null;
        }

    }

    private SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws Exception {
        ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded()));
        ASN1Sequence seq = (ASN1Sequence) is.readObject();
        is.close();
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(seq);
        return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
    }

    DomainCertificate getCACertificate(String domain) {
        DomainCertificate domainCertificate = caCertificateRepository.findOne(domain);
        if (domainCertificate == null) {
            domainCertificate = createCACertificate(domain);
        }
        return domainCertificate;
    }


}
