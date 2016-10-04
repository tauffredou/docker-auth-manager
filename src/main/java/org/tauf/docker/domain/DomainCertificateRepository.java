package org.tauf.docker.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface DomainCertificateRepository  extends JpaRepository<DomainCertificate,String>{

}
