package io.github.asharapov.nexus.casc.internal.model;

import java.util.Date;

public class CertificateVO {
    public Date expiresOn;
    public String fingerprint;
    public String id;
    public Date issuedOn;
    public String issuerCommonName;
    public String issuerOrganization;
    public String issuerOrganizationalUnit;
    public String pem;
    public String serialNumber;
    public String subjectCommonName;
    public String subjectOrganization;
    public String subjectOrganizationalUnit;
}
