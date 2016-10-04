package org.tauf.docker;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.tauf.docker.domain.*;

import javax.servlet.http.HttpServletResponse;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.zip.GZIPOutputStream;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final Logger LOGGER = LoggerFactory.getLogger(ApiController.class);

    @Autowired
    PkiService pki;

    @Autowired
    AutoritiesToRoleMapper autoritiesToRoleMapper;

    @RequestMapping("/version")
    public String version() {
        return "DEV";
    }

    @RequestMapping(value = "/domain/{domain}/server/{name}", method = GET, produces = "application/octet-stream")
    public void registerServer(@PathVariable String domain, @PathVariable String name, HttpServletResponse response) throws Exception {

        ServerCertificate serverCertificate = pki.createServerCertificate(domain, name);
        response.setHeader("Content-Disposition", "attachment; filename=\"" + name + ".tar.gz\"");

        try (TarArchiveOutputStream taos = new TarArchiveOutputStream(
                new GZIPOutputStream(
                        new BufferedOutputStream(
                                response.getOutputStream()
                        )))) {

            taos.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_STAR);
            taos.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);

            addCertToArchive(serverCertificate, taos, "server-cert.pem");
            addKeyToArchive(serverCertificate, taos, "server-key.pem");
            addCaToArchive(serverCertificate, taos, "ca.pem");

            taos.close();

        }
    }

    @RequestMapping(value = "/domain/{domain}/token", method = GET, produces = "application/octet-stream")
    public void token(@PathVariable String domain, Authentication authentication, HttpServletResponse response) throws Exception {

        LOGGER.info(StringUtils.collectionToCommaDelimitedString(authentication.getAuthorities()));



        ClientCertificate serverCertificate = pki.createClientCertificate(domain, authentication.getName(),autoritiesToRoleMapper.getUserRole(domain,authentication));
        response.setHeader("Content-Disposition", "attachment; filename=\"" + authentication.getName() + ".tar.gz\"");

        try (TarArchiveOutputStream taos = new TarArchiveOutputStream(
                new GZIPOutputStream(
                        new BufferedOutputStream(
                                response.getOutputStream()
                        )))) {

            taos.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_STAR);
            taos.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);

            addCertToArchive(serverCertificate, taos, "cert.pem");
            addKeyToArchive(serverCertificate, taos, "key.pem");
            addCaToArchive(serverCertificate, taos, "ca.pem");

            taos.close();

        }
    }

    private void getUSerRole(Authentication authentication) {

    }

    private void addCaToArchive(Certificate serverCertificate, TarArchiveOutputStream taos, String name) throws IOException, CertificateEncodingException {// Add ca
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            try (PemWriter writer = new PemWriter(new OutputStreamWriter(baos))) {
                X509Certificate ca = serverCertificate.getCa().getCertificate();
                writer.writeObject(new PemObject("CERTIFICATE", ca.getEncoded()));
            }
            addDataToArchive(taos, name, baos);
        }
    }

    private void addKeyToArchive(Certificate serverCertificate, TarArchiveOutputStream taos, String name) throws IOException {// Add key
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            try (JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(baos))) {
                PrivateKey key = serverCertificate.getPrivateKey();
                writer.writeObject(key);
            }
            addDataToArchive(taos, name, baos);
        }
    }

    private void addCertToArchive(Certificate certificate, TarArchiveOutputStream taos, String name) throws IOException, CertificateEncodingException {// Add cert
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            try (PemWriter writer = new PemWriter(new OutputStreamWriter(baos))) {
                writer.writeObject(new PemObject("CERTIFICATE", certificate.getCertificate().getEncoded()));
            }
            addDataToArchive(taos, name, baos);
        }
    }

    private void addDataToArchive(TarArchiveOutputStream taos, String filename, ByteArrayOutputStream baos) throws IOException {
        TarArchiveEntry tae = new TarArchiveEntry(filename);
        tae.setSize(baos.size());
        taos.putArchiveEntry(tae);
        taos.write(baos.toByteArray());
        taos.closeArchiveEntry();
    }

    @RequestMapping(value = "/domain/{domain}", method = GET)
    public DomainCertificate registerDomain(@PathVariable String domain) {
        return pki.getCACertificate(domain);
    }

    @RequestMapping(value = "/domain/{domain}/permissions", method = POST)
    public String checkPermissions(@PathVariable String domain, @RequestParam(name = "token") String tokenBase64, @RequestBody String payload) throws IOException {
        Token token = Token.decode(tokenBase64);
        return token.getRole().equals("admin") ? "allow" : "deny";
    }

}
