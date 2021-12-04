/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "glitchedhttps_cacerts.h"

static char* CUSTOM_CA_CERTS = NULL;
static size_t CUSTOM_CA_CERTS_LEN = 0;

static char* CA_CERTS = NULL;
static size_t CA_CERTS_LEN = 0;

void glitchedhttps_set_custom_ca_certs(char* ca_certs)
{
    if (ca_certs == NULL)
    {
        CUSTOM_CA_CERTS = NULL;
        CUSTOM_CA_CERTS_LEN = 0;
        return;
    }

    CUSTOM_CA_CERTS = ca_certs;
    CUSTOM_CA_CERTS_LEN = strlen(ca_certs) + 1;
}

size_t glitchedhttps_get_ca_certs_length()
{
    if (CUSTOM_CA_CERTS != NULL)
    {
        return CUSTOM_CA_CERTS_LEN;
    }

    return CA_CERTS_LEN;
}

const char* glitchedhttps_get_ca_certs()
{
    if (CUSTOM_CA_CERTS != NULL)
    {
        return CUSTOM_CA_CERTS;
    }

    if (CA_CERTS != NULL)
    {
        return CA_CERTS;
    }

    FILE* file = fopen(__FILE__, "r");
    if (file == NULL)
    {
        return "";
    }

    chillbuff stringbuilder;
    if (chillbuff_init(&stringbuilder, 320000, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE) != CHILLBUFF_SUCCESS)
    {
        /* Out of memory! */
        return "";
    }

    char buffer[256];
    int reading = 0;

    while (fgets(buffer, sizeof(buffer), file) != NULL)
    {
        if (strncmp(buffer, "-----BEGIN CERTIFICATES LIST-----", 33) == 0)
        {
            reading = 1;
            continue;
        }

        if (reading)
        {
            chillbuff_push_back(&stringbuilder, buffer, strlen(buffer));
        }

        if (strncmp(buffer, "-----END CERTIFICATES LIST-----", 31) == 0)
        {
            reading = 0;
        }
    }

    CA_CERTS = malloc(stringbuilder.length + 1);
    if (CA_CERTS == NULL)
    {
        /* Out of memory! */
        goto exit;
    }

    memcpy((char*)CA_CERTS, (char*)stringbuilder.array, stringbuilder.length);
    CA_CERTS[stringbuilder.length] = '\0';
    CA_CERTS_LEN = stringbuilder.length + 1;

exit:
    chillbuff_free(&stringbuilder);
    fclose(file);

    return CA_CERTS;
}

/*
 *   This part of the work contains a (modified) version of Mozilla's "certdata.txt" file (see links below)
 *   as a provider of commonly trusted CA root certificates (the same ones that the Firefox browser uses).
 *
 *
 *   Additional custom picks for backup purposes (appended at the end of the above mentioned Mozilla chain; duplicate entries are possible)
 *   were taken from the following sources:
 *
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | CERTIFICATE AUTHORITY    | CERTIFICATES DOWNLOAD URL                                                                                  |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | Let's Encrypt            | https://letsencrypt.org/certificates/                                                                      |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | DigiCert                 | https://www.digicert.com/digicert-root-community-certificates.htm                                          |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | SwissSign                | https://www.swisssign.com/support/ca-prod.html                                                             |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | SSL.com                  | https://www.ssl.com/article/ssl-com-root-certificates/                                                     |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | IdenTrust                | https://www.identrust.com/support/downloads                                                                |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | Comodo                   | https://support.comodo.com/index.php?/Knowledgebase/List/Index/71                                          |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | GoDaddy                  | https://ssl-ccp.godaddy.com/repository?origin=CALLISTO                                                     |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | GlobalSign               | https://support.globalsign.com/customer/portal/articles/1426602-globalsign-root-certificates               |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *   | Amazon Trust Services    | https://www.amazontrust.com/repository/                                                                    |
 *   +--------------------------+------------------------------------------------------------------------------------------------------------+
 *
 *   These custom additional certificates start from the line (this file) containing the text "BEGIN CUSTOM ADDITIONAL CERTS" downwards.
 */

/* ---------------------------------------------------------------------------------------------------------------------------------------- */
/* ---------------------------------------------------------------------------------------------------------------------------------------- */
/* ---------------------------------------------------------------------------------------------------------------------------------------- */

/*
    ##
    ## Bundle of CA Root Certificates
    ##
    ## Certificate data from Mozilla as of: Tue Jan 19 04:12:04 2021 GMT
    ##
    ## This is a bundle of X.509 certificates of public Certificate Authorities
    ## (CA). These were automatically extracted from Mozilla's root certificates
    ## file (certdata.txt).  This file can be found in the mozilla source tree:
    ## https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt
    ##
    ## It contains the certificates in PEM format and therefore
    ## can be directly used with curl / libcurl / php_curl, or with
    ## an Apache+mod_ssl webserver for SSL client authentication.
    ## Just configure this file as the SSLCACertificateFile.
    ##
    ## Conversion done with mk-ca-bundle.pl version 1.28.
    ## SHA256: 3bdc63d1de27058fec943a999a2a8a01fcc6806a611b19221a7727d3d9bbbdfd
    ##


     This modified variant of the Mozilla "certdata.txt" file was taken from the CURL website:

         https://curl.haxx.se/docs/caextract.html

     The original file, as well as infos regarding Mozilla's certificate handling approach can be found here:

         https://wiki.mozilla.org/CA/Included_Certificates

         https://wiki.mozilla.org/CA/Additional_Trust_Changes

         https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/

         https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

     (Links last accessed successfully the 16th of February, 2021)

*/

/*

-----BEGIN CERTIFICATES LIST-----

GlobalSign Root CA
==================
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx
GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkds
b2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNV
BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYD
VQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa
DuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6sc
THAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlb
Kk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNP
c1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrX
gzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUF
AAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6Dj
Y1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyG
j/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhH
hm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveC
X4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----

GlobalSign Root CA - R2
=======================
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xv
YmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2Jh
bFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxT
aWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2ln
bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6
ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozp
s6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjN
S7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CL
TfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6C
ygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9i
YWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjAN
BgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp
9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu
01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG7
9G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7
TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==
-----END CERTIFICATE-----

Entrust.net Premium 2048 Secure Server CA
=========================================
-----BEGIN CERTIFICATE-----
MIIEKjCCAxKgAwIBAgIEOGPe+DANBgkqhkiG9w0BAQUFADCBtDEUMBIGA1UEChMLRW50cnVzdC5u
ZXQxQDA+BgNVBAsUN3d3dy5lbnRydXN0Lm5ldC9DUFNfMjA0OCBpbmNvcnAuIGJ5IHJlZi4gKGxp
bWl0cyBsaWFiLikxJTAjBgNVBAsTHChjKSAxOTk5IEVudHJ1c3QubmV0IExpbWl0ZWQxMzAxBgNV
BAMTKkVudHJ1c3QubmV0IENlcnRpZmljYXRpb24gQXV0aG9yaXR5ICgyMDQ4KTAeFw05OTEyMjQx
NzUwNTFaFw0yOTA3MjQxNDE1MTJaMIG0MRQwEgYDVQQKEwtFbnRydXN0Lm5ldDFAMD4GA1UECxQ3
d3d3LmVudHJ1c3QubmV0L0NQU18yMDQ4IGluY29ycC4gYnkgcmVmLiAobGltaXRzIGxpYWIuKTEl
MCMGA1UECxMcKGMpIDE5OTkgRW50cnVzdC5uZXQgTGltaXRlZDEzMDEGA1UEAxMqRW50cnVzdC5u
ZXQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgKDIwNDgpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEArU1LqRKGsuqjIAcVFmQqK0vRvwtKTY7tgHalZ7d4QMBzQshowNtTK91euHaYNZOL
Gp18EzoOH1u3Hs/lJBQesYGpjX24zGtLA/ECDNyrpUAkAH90lKGdCCmziAv1h3edVc3kw37XamSr
hRSGlVuXMlBvPci6Zgzj/L24ScF2iUkZ/cCovYmjZy/Gn7xxGWC4LeksyZB2ZnuU4q941mVTXTzW
nLLPKQP5L6RQstRIzgUyVYr9smRMDuSYB3Xbf9+5CFVghTAp+XtIpGmG4zU/HoZdenoVve8AjhUi
VBcAkCaTvA5JaJG/+EfTnZVCwQ5N328mz8MYIWJmQ3DW1cAH4QIDAQABo0IwQDAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUVeSB0RGAvtiJuQijMfmhJAkWuXAwDQYJ
KoZIhvcNAQEFBQADggEBADubj1abMOdTmXx6eadNl9cZlZD7Bh/KM3xGY4+WZiT6QBshJ8rmcnPy
T/4xmf3IDExoU8aAghOY+rat2l098c5u9hURlIIM7j+VrxGrD9cv3h8Dj1csHsm7mhpElesYT6Yf
zX1XEC+bBAlahLVu2B064dae0Wx5XnkcFMXj0EyTO2U87d89vqbllRrDtRnDvV5bu/8j72gZyxKT
J1wDLW8w0B62GqzeWvfRqqgnpv55gcR5mTNXuhKwqeBCbJPKVt7+bYQLCIt+jerXmCHG8+c8eS9e
nNFMFY3h7CI3zJpDC5fcgJCNs2ebb0gIFVbPv/ErfF6adulZkMV8gzURZVE=
-----END CERTIFICATE-----

Baltimore CyberTrust Root
=========================
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJRTESMBAGA1UE
ChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3li
ZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoXDTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMC
SUUxEjAQBgNVBAoTCUJhbHRpbW9yZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFs
dGltb3JlIEN5YmVyVHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKME
uyKrmD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjrIZ3AQSsB
UnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeKmpYcqWe4PwzV9/lSEy/C
G9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSuXmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9
XbIGevOF6uvUA65ehD5f/xXtabz5OTZydc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjpr
l3RjM71oGDHweI12v/yejl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoI
VDaGezq1BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEB
BQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT929hkTI7gQCvlYpNRh
cL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3WgxjkzSswF07r51XgdIGn9w/xZchMB5
hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsa
Y71k5h+3zvDyny67G7fyUIhzksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9H
RCwBXbsdtTLSR9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp
-----END CERTIFICATE-----

Entrust Root Certification Authority
====================================
-----BEGIN CERTIFICATE-----
MIIEkTCCA3mgAwIBAgIERWtQVDANBgkqhkiG9w0BAQUFADCBsDELMAkGA1UEBhMCVVMxFjAUBgNV
BAoTDUVudHJ1c3QsIEluYy4xOTA3BgNVBAsTMHd3dy5lbnRydXN0Lm5ldC9DUFMgaXMgaW5jb3Jw
b3JhdGVkIGJ5IHJlZmVyZW5jZTEfMB0GA1UECxMWKGMpIDIwMDYgRW50cnVzdCwgSW5jLjEtMCsG
A1UEAxMkRW50cnVzdCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA2MTEyNzIwMjM0
MloXDTI2MTEyNzIwNTM0MlowgbAxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMu
MTkwNwYDVQQLEzB3d3cuZW50cnVzdC5uZXQvQ1BTIGlzIGluY29ycG9yYXRlZCBieSByZWZlcmVu
Y2UxHzAdBgNVBAsTFihjKSAyMDA2IEVudHJ1c3QsIEluYy4xLTArBgNVBAMTJEVudHJ1c3QgUm9v
dCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALaVtkNC+sZtKm9I35RMOVcF7sN5EUFoNu3s/poBj6E4KPz3EEZmLk0eGrEaTsbRwJWIsMn/MYsz
A9u3g3s+IIRe7bJWKKf44LlAcTfFy0cOlypowCKVYhXbR9n10Cv/gkvJrT7eTNuQgFA/CYqEAOww
Cj0Yzfv9KlmaI5UXLEWeH25DeW0MXJj+SKfFI0dcXv1u5x609mhF0YaDW6KKjbHjKYD+JXGIrb68
j6xSlkuqUY3kEzEZ6E5Nn9uss2rVvDlUccp6en+Q3X0dgNmBu1kmwhH+5pPi94DkZfs0Nw4pgHBN
rziGLp5/V6+eF67rHMsoIV+2HNjnogQi+dPa2MsCAwEAAaOBsDCBrTAOBgNVHQ8BAf8EBAMCAQYw
DwYDVR0TAQH/BAUwAwEB/zArBgNVHRAEJDAigA8yMDA2MTEyNzIwMjM0MlqBDzIwMjYxMTI3MjA1
MzQyWjAfBgNVHSMEGDAWgBRokORnpKZTgMeGZqTx90tD+4S9bTAdBgNVHQ4EFgQUaJDkZ6SmU4DH
hmak8fdLQ/uEvW0wHQYJKoZIhvZ9B0EABBAwDhsIVjcuMTo0LjADAgSQMA0GCSqGSIb3DQEBBQUA
A4IBAQCT1DCw1wMgKtD5Y+iRDAUgqV8ZyntyTtSx29CW+1RaGSwMCPeyvIWonX9tO1KzKtvn1ISM
Y/YPyyYBkVBs9F8U4pN0wBOeMDpQ47RgxRzwIkSNcUesyBrJ6ZuaAGAT/3B+XxFNSRuzFVJ7yVTa
v52Vr2ua2J7p8eRDjeIRRDq/r72DQnNSi6q7pynP9WQcCk3RvKqsnyrQ/39/2n3qse0wJcGE2jTS
W3iDVuycNsMm4hH2Z0kdkquM++v/eu6FSqdQgPCnXEqULl8FmTxSQeDNtGPPAUO6nIPcj2A781q0
tHuu2guQOHXvgR1m0vdXcDazv/wor3ElhVsT/h5/WrQ8
-----END CERTIFICATE-----

Comodo AAA Services root
========================
-----BEGIN CERTIFICATE-----
MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwS
R3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0Eg
TGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAw
MFoXDTI4MTIzMTIzNTk1OVowezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hl
c3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQuaBtDFcCLNSS1UY8y2bmhG
C1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe3M/vg4aijJRPn2jymJBGhCfHdr/jzDUs
i14HZGWCwEiwqJH5YZ92IFCokcdmtet4YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszW
Y19zjNoFmag4qMsXeDZRrOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjH
Ypy+g8cmez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQUoBEK
Iz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wewYDVR0f
BHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNl
cy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29tb2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2Vz
LmNybDANBgkqhkiG9w0BAQUFAAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm
7l3sAg9g1o1QGE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz
Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2G9w84FoVxp7Z
8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsil2D4kF501KKaU73yqWjgom7C
12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==
-----END CERTIFICATE-----

QuoVadis Root CA
================
-----BEGIN CERTIFICATE-----
MIIF0DCCBLigAwIBAgIEOrZQizANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJCTTEZMBcGA1UE
ChMQUXVvVmFkaXMgTGltaXRlZDElMCMGA1UECxMcUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
eTEuMCwGA1UEAxMlUXVvVmFkaXMgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wMTAz
MTkxODMzMzNaFw0yMTAzMTcxODMzMzNaMH8xCzAJBgNVBAYTAkJNMRkwFwYDVQQKExBRdW9WYWRp
cyBMaW1pdGVkMSUwIwYDVQQLExxSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MS4wLAYDVQQD
EyVRdW9WYWRpcyBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAv2G1lVO6V/z68mcLOhrfEYBklbTRvM16z/Ypli4kVEAkOPcahdxYTMuk
J0KX0J+DisPkBgNbAKVRHnAEdOLB1Dqr1607BxgFjv2DrOpm2RgbaIr1VxqYuvXtdj182d6UajtL
F8HVj71lODqV0D1VNk7feVcxKh7YWWVJWCCYfqtffp/p1k3sg3Spx2zY7ilKhSoGFPlU5tPaZQeL
YzcS19Dsw3sgQUSj7cugF+FxZc4dZjH3dgEZyH0DWLaVSR2mEiboxgx24ONmy+pdpibu5cxfvWen
AScOospUxbF6lR1xHkopigPcakXBpBlebzbNw6Kwt/5cOOJSvPhEQ+aQuwIDAQABo4ICUjCCAk4w
PQYIKwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwczovL29jc3AucXVvdmFkaXNvZmZzaG9y
ZS5jb20wDwYDVR0TAQH/BAUwAwEB/zCCARoGA1UdIASCAREwggENMIIBCQYJKwYBBAG+WAABMIH7
MIHUBggrBgEFBQcCAjCBxxqBxFJlbGlhbmNlIG9uIHRoZSBRdW9WYWRpcyBSb290IENlcnRpZmlj
YXRlIGJ5IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJs
ZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRpb24gcHJh
Y3RpY2VzLCBhbmQgdGhlIFF1b1ZhZGlzIENlcnRpZmljYXRlIFBvbGljeS4wIgYIKwYBBQUHAgEW
Fmh0dHA6Ly93d3cucXVvdmFkaXMuYm0wHQYDVR0OBBYEFItLbe3TKbkGGew5Oanwl4Rqy+/fMIGu
BgNVHSMEgaYwgaOAFItLbe3TKbkGGew5Oanwl4Rqy+/foYGEpIGBMH8xCzAJBgNVBAYTAkJNMRkw
FwYDVQQKExBRdW9WYWRpcyBMaW1pdGVkMSUwIwYDVQQLExxSb290IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MS4wLAYDVQQDEyVRdW9WYWRpcyBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5ggQ6
tlCLMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQUFAAOCAQEAitQUtf70mpKnGdSkfnIYj9lo
fFIk3WdvOXrEql494liwTXCYhGHoG+NpGA7O+0dQoE7/8CQfvbLO9Sf87C9TqnN7Az10buYWnuul
LsS/VidQK2K6vkscPFVcQR0kvoIgR13VRH56FmjffU1RcHhXHTMe/QKZnAzNCgVPx7uOpHX6Sm2x
gI4JVrmcGmD+XcHXetwReNDWXcG31a0ymQM6isxUJTkxgXsTIlG6Rmyhu576BGxJJnSP0nPrzDCi
5upZIof4l/UO/erMkqQWxFIY6iHOsfHmhIHluqmGKPJDWl0Snawe2ajlCmqnf6CHKc/yiU3U7MXi
5nrQNiOKSnQ2+Q==
-----END CERTIFICATE-----

QuoVadis Root CA 2
==================
-----BEGIN CERTIFICATE-----
MIIFtzCCA5+gAwIBAgICBQkwDQYJKoZIhvcNAQEFBQAwRTELMAkGA1UEBhMCQk0xGTAXBgNVBAoT
EFF1b1ZhZGlzIExpbWl0ZWQxGzAZBgNVBAMTElF1b1ZhZGlzIFJvb3QgQ0EgMjAeFw0wNjExMjQx
ODI3MDBaFw0zMTExMjQxODIzMzNaMEUxCzAJBgNVBAYTAkJNMRkwFwYDVQQKExBRdW9WYWRpcyBM
aW1pdGVkMRswGQYDVQQDExJRdW9WYWRpcyBSb290IENBIDIwggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQCaGMpLlA0ALa8DKYrwD4HIrkwZhR0In6spRIXzL4GtMh6QRr+jhiYaHv5+HBg6
XJxgFyo6dIMzMH1hVBHL7avg5tKifvVrbxi3Cgst/ek+7wrGsxDp3MJGF/hd/aTa/55JWpzmM+Yk
lvc/ulsrHHo1wtZn/qtmUIttKGAr79dgw8eTvI02kfN/+NsRE8Scd3bBrrcCaoF6qUWD4gXmuVbB
lDePSHFjIuwXZQeVikvfj8ZaCuWw419eaxGrDPmF60Tp+ARz8un+XJiM9XOva7R+zdRcAitMOeGy
lZUtQofX1bOQQ7dsE/He3fbE+Ik/0XX1ksOR1YqI0JDs3G3eicJlcZaLDQP9nL9bFqyS2+r+eXyt
66/3FsvbzSUr5R/7mp/iUcw6UwxI5g69ybR2BlLmEROFcmMDBOAENisgGQLodKcftslWZvB1Jdxn
wQ5hYIizPtGo/KPaHbDRsSNU30R2be1B2MGyIrZTHN81Hdyhdyox5C315eXbyOD/5YDXC2Og/zOh
D7osFRXql7PSorW+8oyWHhqPHWykYTe5hnMz15eWniN9gqRMgeKh0bpnX5UHoycR7hYQe7xFSkyy
BNKr79X9DFHOUGoIMfmR2gyPZFwDwzqLID9ujWc9Otb+fVuIyV77zGHcizN300QyNQliBJIWENie
J0f7OyHj+OsdWwIDAQABo4GwMIGtMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgEGMB0GA1Ud
DgQWBBQahGK8SEwzJQTU7tD2A8QZRtGUazBuBgNVHSMEZzBlgBQahGK8SEwzJQTU7tD2A8QZRtGU
a6FJpEcwRTELMAkGA1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxGzAZBgNVBAMT
ElF1b1ZhZGlzIFJvb3QgQ0EgMoICBQkwDQYJKoZIhvcNAQEFBQADggIBAD4KFk2fBluornFdLwUv
Z+YTRYPENvbzwCYMDbVHZF34tHLJRqUDGCdViXh9duqWNIAXINzng/iN/Ae42l9NLmeyhP3ZRPx3
UIHmfLTJDQtyU/h2BwdBR5YM++CCJpNVjP4iH2BlfF/nJrP3MpCYUNQ3cVX2kiF495V5+vgtJodm
VjB3pjd4M1IQWK4/YY7yarHvGH5KWWPKjaJW1acvvFYfzznB4vsKqBUsfU16Y8Zsl0Q80m/DShcK
+JDSV6IZUaUtl0HaB0+pUNqQjZRG4T7wlP0QADj1O+hA4bRuVhogzG9Yje0uRY/W6ZM/57Es3zrW
IozchLsib9D45MY56QSIPMO661V6bYCZJPVsAfv4l7CUW+v90m/xd2gNNWQjrLhVoQPRTUIZ3Ph1
WVaj+ahJefivDrkRoHy3au000LYmYjgahwz46P0u05B/B5EqHdZ+XIWDmbA4CD/pXvk1B+TJYm5X
f6dQlfe6yJvmjqIBxdZmv3lh8zwc4bmCXF2gw+nYSL0ZohEUGW6yhhtoPkg3Goi3XZZenMfvJ2II
4pEZXNLxId26F0KCl3GBUzGpn/Z9Yr9y4aOTHcyKJloJONDO1w2AFrR4pTqHTI2KpdVGl/IsELm8
VCLAAVBpQ570su9t+Oza8eOx79+Rj1QqCyXBJhnEUhAFZdWCEOrCMc0u
-----END CERTIFICATE-----

QuoVadis Root CA 3
==================
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----

Security Communication Root CA
==============================
-----BEGIN CERTIFICATE-----
MIIDWjCCAkKgAwIBAgIBADANBgkqhkiG9w0BAQUFADBQMQswCQYDVQQGEwJKUDEYMBYGA1UEChMP
U0VDT00gVHJ1c3QubmV0MScwJQYDVQQLEx5TZWN1cml0eSBDb21tdW5pY2F0aW9uIFJvb3RDQTEw
HhcNMDMwOTMwMDQyMDQ5WhcNMjMwOTMwMDQyMDQ5WjBQMQswCQYDVQQGEwJKUDEYMBYGA1UEChMP
U0VDT00gVHJ1c3QubmV0MScwJQYDVQQLEx5TZWN1cml0eSBDb21tdW5pY2F0aW9uIFJvb3RDQTEw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzs/5/022x7xZ8V6UMbXaKL0u/ZPtM7orw
8yl89f/uKuDp6bpbZCKamm8sOiZpUQWZJtzVHGpxxpp9Hp3dfGzGjGdnSj74cbAZJ6kJDKaVv0uM
DPpVmDvY6CKhS3E4eayXkmmziX7qIWgGmBSWh9JhNrxtJ1aeV+7AwFb9Ms+k2Y7CI9eNqPPYJayX
5HA49LY6tJ07lyZDo6G8SVlyTCMwhwFY9k6+HGhWZq/NQV3Is00qVUarH9oe4kA92819uZKAnDfd
DJZkndwi92SL32HeFZRSFaB9UslLqCHJxrHty8OVYNEP8Ktw+N/LTX7s1vqr2b1/VPKl6Xn62dZ2
JChzAgMBAAGjPzA9MB0GA1UdDgQWBBSgc0mZaNyFW2XjmygvV5+9M7wHSDALBgNVHQ8EBAMCAQYw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAaECpqLvkT115swW1F7NgE+vGkl3g
0dNq/vu+m22/xwVtWSDEHPC32oRYAmP6SBbvT6UL90qY8j+eG61Ha2POCEfrUj94nK9NrvjVT8+a
mCoQQTlSxN3Zmw7vkwGusi7KaEIkQmywszo+zenaSMQVy+n5Bw+SUEmK3TGXX8npN6o7WWWXlDLJ
s58+OmJYxUmtYg5xpTKqL8aJdkNAExNnPaJUJRDL8Try2frbSVa7pv6nQTXD4IhhyYjH3zYQIphZ
6rBK+1YWc26sTfcioU+tHXotRSflMMFe8toTyyVCUZVHA4xsIcx0Qu1T/zOLjw9XARYvz6buyXAi
FL39vmwLAw==
-----END CERTIFICATE-----

Sonera Class 2 Root CA
======================
-----BEGIN CERTIFICATE-----
MIIDIDCCAgigAwIBAgIBHTANBgkqhkiG9w0BAQUFADA5MQswCQYDVQQGEwJGSTEPMA0GA1UEChMG
U29uZXJhMRkwFwYDVQQDExBTb25lcmEgQ2xhc3MyIENBMB4XDTAxMDQwNjA3Mjk0MFoXDTIxMDQw
NjA3Mjk0MFowOTELMAkGA1UEBhMCRkkxDzANBgNVBAoTBlNvbmVyYTEZMBcGA1UEAxMQU29uZXJh
IENsYXNzMiBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJAXSjWdyvANlsdE+hY3
/Ei9vX+ALTU74W+oZ6m/AxxNjG8yR9VBaKQTBME1DJqEQ/xcHf+Js+gXGM2RX/uJ4+q/Tl18GybT
dXnt5oTjV+WtKcT0OijnpXuENmmz/V52vaMtmdOQTiMofRhj8VQ7Jp12W5dCsv+u8E7s3TmVToMG
f+dJQMjFAbJUWmYdPfz56TwKnoG4cPABi+QjVHzIrviQHgCWctRUz2EjvOr7nQKV0ba5cTppCD8P
tOFCx4j1P5iop7oc4HFx71hXgVB6XGt0Rg6DA5jDjqhu8nYybieDwnPz3BjotJPqdURrBGAgcVeH
nfO+oJAjPYok4doh28MCAwEAAaMzMDEwDwYDVR0TAQH/BAUwAwEB/zARBgNVHQ4ECgQISqCqWITT
XjwwCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBBQUAA4IBAQBazof5FnIVV0sd2ZvnoiYw7JNn39Yt
0jSv9zilzqsWuasvfDXLrNAPtEwr/IDva4yRXzZ299uzGxnq9LIR/WFxRL8oszodv7ND6J+/3DEI
cbCdjdY0RzKQxmUk96BKfARzjzlvF4xytb1LyHr4e4PDKE6cCepnP7JnBBvDFNr450kkkdAdavph
Oe9r5yF1BgfYErQhIHBCcYHaPJo2vqZbDWpsmh+Re/n570K6Tk6ezAyNlNzZRZxe7EJQY670XcSx
EtzKO6gunRRaBXW37Ndj4ro1tgQIkejanZz2ZrUYrAqmVCY0M9IbwdR/GjqOC6oybtv8TyWf2TLH
llpwrN9M
-----END CERTIFICATE-----

XRamp Global CA Root
====================
-----BEGIN CERTIFICATE-----
MIIEMDCCAxigAwIBAgIQUJRs7Bjq1ZxN1ZfvdY+grTANBgkqhkiG9w0BAQUFADCBgjELMAkGA1UE
BhMCVVMxHjAcBgNVBAsTFXd3dy54cmFtcHNlY3VyaXR5LmNvbTEkMCIGA1UEChMbWFJhbXAgU2Vj
dXJpdHkgU2VydmljZXMgSW5jMS0wKwYDVQQDEyRYUmFtcCBHbG9iYWwgQ2VydGlmaWNhdGlvbiBB
dXRob3JpdHkwHhcNMDQxMTAxMTcxNDA0WhcNMzUwMTAxMDUzNzE5WjCBgjELMAkGA1UEBhMCVVMx
HjAcBgNVBAsTFXd3dy54cmFtcHNlY3VyaXR5LmNvbTEkMCIGA1UEChMbWFJhbXAgU2VjdXJpdHkg
U2VydmljZXMgSW5jMS0wKwYDVQQDEyRYUmFtcCBHbG9iYWwgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
dHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCYJB69FbS638eMpSe2OAtp87ZOqCwu
IR1cRN8hXX4jdP5efrRKt6atH67gBhbim1vZZ3RrXYCPKZ2GG9mcDZhtdhAoWORlsH9KmHmf4MMx
foArtYzAQDsRhtDLooY2YKTVMIJt2W7QDxIEM5dfT2Fa8OT5kavnHTu86M/0ay00fOJIYRyO82FE
zG+gSqmUsE3a56k0enI4qEHMPJQRfevIpoy3hsvKMzvZPTeL+3o+hiznc9cKV6xkmxnr9A8ECIqs
AxcZZPRaJSKNNCyy9mgdEm3Tih4U2sSPpuIjhdV6Db1q4Ons7Be7QhtnqiXtRYMh/MHJfNViPvry
xS3T/dRlAgMBAAGjgZ8wgZwwEwYJKwYBBAGCNxQCBAYeBABDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
EwEB/wQFMAMBAf8wHQYDVR0OBBYEFMZPoj0GY4QJnM5i5ASsjVy16bYbMDYGA1UdHwQvMC0wK6Ap
oCeGJWh0dHA6Ly9jcmwueHJhbXBzZWN1cml0eS5jb20vWEdDQS5jcmwwEAYJKwYBBAGCNxUBBAMC
AQEwDQYJKoZIhvcNAQEFBQADggEBAJEVOQMBG2f7Shz5CmBbodpNl2L5JFMn14JkTpAuw0kbK5rc
/Kh4ZzXxHfARvbdI4xD2Dd8/0sm2qlWkSLoC295ZLhVbO50WfUfXN+pfTXYSNrsf16GBBEYgoyxt
qZ4Bfj8pzgCT3/3JknOJiWSe5yvkHJEs0rnOfc5vMZnT5r7SHpDwCRR5XCOrTdLaIR9NmXmd4c8n
nxCbHIgNsIpkQTG4DmyQJKSbXHGPurt+HBvbaoAPIbzp26a3QPSyi6mx5O+aGtA9aZnuqCij4Tyz
8LIRnM98QObd50N9otg6tamN8jSZxNQQ4Qb9CYQQO+7ETPTsJ3xCwnR8gooJybQDJbw=
-----END CERTIFICATE-----

Go Daddy Class 2 CA
===================
-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIBADANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMY
VGhlIEdvIERhZGR5IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRp
ZmljYXRpb24gQXV0aG9yaXR5MB4XDTA0MDYyOTE3MDYyMFoXDTM0MDYyOTE3MDYyMFowYzELMAkG
A1UEBhMCVVMxITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28g
RGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQAD
ggENADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XCAPVYYYwhv
2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux6wwdhFJ2+qN1j3hybX2C32
qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLOtXiEqITLdiOr18SPaAIBQi2XKVlOARFmR6j
YGB0xUGlcmIbYsUfb18aQr4CUWWoriMYavx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmY
vLEHZ6IVDd2gWMZEewo+YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjgcAwgb0wHQYDVR0O
BBYEFNLEsNKR1EwRcbNhyz2h/t2oatTjMIGNBgNVHSMEgYUwgYKAFNLEsNKR1EwRcbNhyz2h/t2o
atTjoWekZTBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYVGhlIEdvIERhZGR5IEdyb3VwLCBJbmMu
MTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5ggEAMAwG
A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBADJL87LKPpH8EsahB4yOd6AzBhRckB4Y9wim
PQoZ+YeAEW5p5JYXMP80kWNyOO7MHAGjHZQopDH2esRU1/blMVgDoszOYtuURXO1v0XJJLXVggKt
I3lpjbi2Tc7PTMozI+gciKqdi0FuFskg5YmezTvacPd+mSYgFFQlq25zheabIZ0KbIIOqPjCDPoQ
HmyW74cNxA9hi63ugyuV+I6ShHI56yDqg+2DzZduCLzrTia2cyvk0/ZM/iZx4mERdEr/VxqHD3VI
Ls9RaRegAhJhldXRQLIQTO7ErBBDpqWeCtWVYpoNz4iCxTIM5CufReYNnyicsbkqWletNw+vHX/b
vZ8=
-----END CERTIFICATE-----

Starfield Class 2 CA
====================
-----BEGIN CERTIFICATE-----
MIIEDzCCAvegAwIBAgIBADANBgkqhkiG9w0BAQUFADBoMQswCQYDVQQGEwJVUzElMCMGA1UEChMc
U3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjEyMDAGA1UECxMpU3RhcmZpZWxkIENsYXNzIDIg
Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDQwNjI5MTczOTE2WhcNMzQwNjI5MTczOTE2WjBo
MQswCQYDVQQGEwJVUzElMCMGA1UEChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjEyMDAG
A1UECxMpU3RhcmZpZWxkIENsYXNzIDIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEgMA0GCSqG
SIb3DQEBAQUAA4IBDQAwggEIAoIBAQC3Msj+6XGmBIWtDBFk385N78gDGIc/oav7PKaf8MOh2tTY
bitTkPskpD6E8J7oX+zlJ0T1KKY/e97gKvDIr1MvnsoFAZMej2YcOadN+lq2cwQlZut3f+dZxkqZ
JRRU6ybH838Z1TBwj6+wRir/resp7defqgSHo9T5iaU0X9tDkYI22WY8sbi5gv2cOj4QyDvvBmVm
epsZGD3/cVE8MC5fvj13c7JdBmzDI1aaK4UmkhynArPkPw2vCHmCuDY96pzTNbO8acr1zJ3o/WSN
F4Azbl5KXZnJHoe0nRrA1W4TNSNe35tfPe/W93bC6j67eA0cQmdrBNj41tpvi/JEoAGrAgEDo4HF
MIHCMB0GA1UdDgQWBBS/X7fRzt0fhvRbVazc1xDCDqmI5zCBkgYDVR0jBIGKMIGHgBS/X7fRzt0f
hvRbVazc1xDCDqmI56FspGowaDELMAkGA1UEBhMCVVMxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNo
bm9sb2dpZXMsIEluYy4xMjAwBgNVBAsTKVN0YXJmaWVsZCBDbGFzcyAyIENlcnRpZmljYXRpb24g
QXV0aG9yaXR5ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAAWdP4id0ckaVaGs
afPzWdqbAYcaT1epoXkJKtv3L7IezMdeatiDh6GX70k1PncGQVhiv45YuApnP+yz3SFmH8lU+nLM
PUxA2IGvd56Deruix/U0F47ZEUD0/CwqTRV/p2JdLiXTAAsgGh1o+Re49L2L7ShZ3U0WixeDyLJl
xy16paq8U4Zt3VekyvggQQto8PT7dL5WXXp59fkdheMtlb71cZBDzI0fmgAKhynpVSJYACPq4xJD
KVtHCN2MQWplBqjlIapBtJUhlbl90TSrE9atvNziPTnNvT51cKEYWQPJIrSPnNVeKtelttQKbfi3
QBFGmh95DmK/D5fs4C8fF5Q=
-----END CERTIFICATE-----

DigiCert Assured ID Root CA
===========================
-----BEGIN CERTIFICATE-----
MIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0BAQUFADBlMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQw
IgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzEx
MTEwMDAwMDAwWjBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
ExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg+XESpa7cJpSIqvTO
9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lTXDGEKvYPmDI2dsze3Tyoou9q+yHy
UmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5a3/UsDg+wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW
/lmci3Zt1/GiSw0r/wty2p5g0I6QNcZ4VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpy
oeb6pNnVFzF1roV9Iq4/AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whf
GHdPAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRF
66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkq
hkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3cmbYMuRCdWKuh+vy1dneVrOfzM4UKLkNl2Bc
EkxY5NM9g0lFWJc1aRqoR+pWxnmrEthngYTffwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38Fn
SbNd67IJKusm7Xi+fT8r87cmNW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i
8b5QZ7dsvfPxH2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu838fYxAe
+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw8g==
-----END CERTIFICATE-----

DigiCert Global Root CA
=======================
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAw
HgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBDQTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAw
MDAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
dy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsBCSDMAZOn
TjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97nh6Vfe63SKMI2tavegw5
BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt43C/dxC//AH2hdmoRBBYMql1GNXRor5H
4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7PT19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y
7vrTC0LUq7dBMtoM1O/4gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQAB
o2MwYTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbRTLtm
8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUwDQYJKoZIhvcNAQEF
BQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/EsrhMAtudXH/vTBH1jLuG2cenTnmCmr
EbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIt
tep3Sp+dWOIrWcBAI+0tKIJFPnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886
UAb3LujEV0lsYSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----

DigiCert High Assurance EV Root CA
==================================
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSsw
KQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAw
MFoXDTMxMTExMDAwMDAwMFowbDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFu
Y2UgRVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm+9S75S0t
Mqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTWPNt0OKRKzE0lgvdKpVMS
OO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEMxChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3
MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFBIk5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQ
NAQTXKFx01p8VdteZOE3hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUe
h10aUAsgEsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSY
JhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3NecnzyIZgYIVyHbIUf4KmeqvxgydkAQ
V8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6zeM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFp
myPInngiK3BD41VHMWEZ71jFhS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkK
mNEVX58Svnw2Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe
vEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep+OkuE6N36B9K
-----END CERTIFICATE-----

DST Root CA X3
==============
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/MSQwIgYDVQQK
ExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4X
DTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVowPzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1
cmUgVHJ1c3QgQ28uMRcwFQYDVQQDEw5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmT
rE4Orz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEqOLl5CjH9
UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9bxiqKqy69cK3FCxolkHRy
xXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40d
utolucbY38EVAjqr2m7xPi71XAicPNaDaeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQ
MA0GCSqGSIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69ikug
dB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXrAvHRAosZy5Q6XkjE
GB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZzR8srzJmwN0jP41ZL9c8PDHIyh8bw
RLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubS
fZGL+T0yjWW06XyxV3bqxbYoOb8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----

SwissSign Gold CA - G2
======================
-----BEGIN CERTIFICATE-----
MIIFujCCA6KgAwIBAgIJALtAHEP1Xk+wMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkNIMRUw
EwYDVQQKEwxTd2lzc1NpZ24gQUcxHzAdBgNVBAMTFlN3aXNzU2lnbiBHb2xkIENBIC0gRzIwHhcN
MDYxMDI1MDgzMDM1WhcNMzYxMDI1MDgzMDM1WjBFMQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dp
c3NTaWduIEFHMR8wHQYDVQQDExZTd2lzc1NpZ24gR29sZCBDQSAtIEcyMIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr+TufoskDhJuqVAtFkQ7kpJcyrhdhJJCEyq8ZVeCQD5XJM1QiyUq
t2/876LQwB8CJEoTlo8jE+YoWACjR8cGp4QjK7u9lit/VcyLwVcfDmJlD909Vopz2q5+bbqBHH5C
jCA12UNNhPqE21Is8w4ndwtrvxEvcnifLtg+5hg3Wipy+dpikJKVyh+c6bM8K8vzARO/Ws/BtQpg
vd21mWRTuKCWs2/iJneRjOBiEAKfNA+k1ZIzUd6+jbqEemA8atufK+ze3gE/bk3lUIbLtK/tREDF
ylqM2tIrfKjuvqblCqoOpd8FUrdVxyJdMmqXl2MT28nbeTZ7hTpKxVKJ+STnnXepgv9VHKVxaSvR
AiTysybUa9oEVeXBCsdtMDeQKuSeFDNeFhdVxVu1yzSJkvGdJo+hB9TGsnhQ2wwMC3wLjEHXuend
jIj3o02yMszYF9rNt85mndT9Xv+9lz4pded+p2JYryU0pUHHPbwNUMoDAw8IWh+Vc3hiv69yFGkO
peUDDniOJihC8AcLYiAQZzlG+qkDzAQ4embvIIO1jEpWjpEA/I5cgt6IoMPiaG59je883WX0XaxR
7ySArqpWl2/5rX3aYT+YdzylkbYcjCbaZaIJbcHiVOO5ykxMgI93e2CaHt+28kgeDrpOVG2Y4OGi
GqJ3UM/EY5LsRxmd6+ZrzsECAwEAAaOBrDCBqTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUw
AwEB/zAdBgNVHQ4EFgQUWyV7lqRlUX64OfPAeGZe6Drn8O4wHwYDVR0jBBgwFoAUWyV7lqRlUX64
OfPAeGZe6Drn8O4wRgYDVR0gBD8wPTA7BglghXQBWQECAQEwLjAsBggrBgEFBQcCARYgaHR0cDov
L3JlcG9zaXRvcnkuc3dpc3NzaWduLmNvbS8wDQYJKoZIhvcNAQEFBQADggIBACe645R88a7A3hfm
5djV9VSwg/S7zV4Fe0+fdWavPOhWfvxyeDgD2StiGwC5+OlgzczOUYrHUDFu4Up+GC9pWbY9ZIEr
44OE5iKHjn3g7gKZYbge9LgriBIWhMIxkziWMaa5O1M/wySTVltpkuzFwbs4AOPsF6m43Md8AYOf
Mke6UiI0HTJ6CVanfCU2qT1L2sCCbwq7EsiHSycR+R4tx5M/nttfJmtS2S6K8RTGRI0Vqbe/vd6m
Gu6uLftIdxf+u+yvGPUqUfA5hJeVbG4bwyvEdGB5JbAKJ9/fXtI5z0V9QkvfsywexcZdylU6oJxp
mo/a77KwPJ+HbBIrZXAVUjEaJM9vMSNQH4xPjyPDdEFjHFWoFN0+4FFQz/EbMFYOkrCChdiDyyJk
vC24JdVUorgG6q2SpCSgwYa1ShNqR88uC1aVVMvOmttqtKay20EIhid392qgQmwLOM7XdVAyksLf
KzAiSNDVQTglXaTpXZ/GlHXQRf0wl0OPkKsKx4ZzYEppLd6leNcG2mqeSz53OiATIgHQv2ieY2Br
NU0LbbqhPcCT4H8js1WtciVORvnSFu+wZMEBnunKoGqYDs/YYPIvSbjkQuE4NRb0yG5P94FW6Lqj
viOvrv1vA+ACOzB2+httQc8Bsem4yWb02ybzOqR08kkkW8mw0FfB+j564ZfJ
-----END CERTIFICATE-----

SwissSign Silver CA - G2
========================
-----BEGIN CERTIFICATE-----
MIIFvTCCA6WgAwIBAgIITxvUL1S7L0swDQYJKoZIhvcNAQEFBQAwRzELMAkGA1UEBhMCQ0gxFTAT
BgNVBAoTDFN3aXNzU2lnbiBBRzEhMB8GA1UEAxMYU3dpc3NTaWduIFNpbHZlciBDQSAtIEcyMB4X
DTA2MTAyNTA4MzI0NloXDTM2MTAyNTA4MzI0NlowRzELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFN3
aXNzU2lnbiBBRzEhMB8GA1UEAxMYU3dpc3NTaWduIFNpbHZlciBDQSAtIEcyMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEAxPGHf9N4Mfc4yfjDmUO8x/e8N+dOcbpLj6VzHVxumK4DV644
N0MvFz0fyM5oEMF4rhkDKxD6LHmD9ui5aLlV8gREpzn5/ASLHvGiTSf5YXu6t+WiE7brYT7QbNHm
+/pe7R20nqA1W6GSy/BJkv6FCgU+5tkL4k+73JU3/JHpMjUi0R86TieFnbAVlDLaYQ1HTWBCrpJH
6INaUFjpiou5XaHc3ZlKHzZnu0jkg7Y360g6rw9njxcH6ATK72oxh9TAtvmUcXtnZLi2kUpCe2Uu
MGoM9ZDulebyzYLs2aFK7PayS+VFheZteJMELpyCbTapxDFkH4aDCyr0NQp4yVXPQbBH6TCfmb5h
qAaEuSh6XzjZG6k4sIN/c8HDO0gqgg8hm7jMqDXDhBuDsz6+pJVpATqJAHgE2cn0mRmrVn5bi4Y5
FZGkECwJMoBgs5PAKrYYC51+jUnyEEp/+dVGLxmSo5mnJqy7jDzmDrxHB9xzUfFwZC8I+bRHHTBs
ROopN4WSaGa8gzj+ezku01DwH/teYLappvonQfGbGHLy9YR0SslnxFSuSGTfjNFusB3hB48IHpmc
celM2KX3RxIfdNFRnobzwqIjQAtz20um53MGjMGg6cFZrEb65i/4z3GcRm25xBWNOHkDRUjvxF3X
CO6HOSKGsg0PWEP3calILv3q1h8CAwEAAaOBrDCBqTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQUF6DNweRBtjpbO8tFnb0cwpj6hlgwHwYDVR0jBBgwFoAUF6DNweRB
tjpbO8tFnb0cwpj6hlgwRgYDVR0gBD8wPTA7BglghXQBWQEDAQEwLjAsBggrBgEFBQcCARYgaHR0
cDovL3JlcG9zaXRvcnkuc3dpc3NzaWduLmNvbS8wDQYJKoZIhvcNAQEFBQADggIBAHPGgeAn0i0P
4JUw4ppBf1AsX19iYamGamkYDHRJ1l2E6kFSGG9YrVBWIGrGvShpWJHckRE1qTodvBqlYJ7YH39F
kWnZfrt4csEGDyrOj4VwYaygzQu4OSlWhDJOhrs9xCrZ1x9y7v5RoSJBsXECYxqCsGKrXlcSH9/L
3XWgwF15kIwb4FDm3jH+mHtwX6WQ2K34ArZv02DdQEsixT2tOnqfGhpHkXkzuoLcMmkDlm4fS/Bx
/uNncqCxv1yL5PqZIseEuRuNI5c/7SXgz2W79WEE790eslpBIlqhn10s6FvJbakMDHiqYMZWjwFa
DGi8aRl5xB9+lwW/xekkUV7U1UtT7dkjWjYDZaPBA61BMPNGG4WQr2W11bHkFlt4dR2Xem1ZqSqP
e97Dh4kQmUlzeMg9vVE1dCrV8X5pGyq7O70luJpaPXJhkGaH7gzWTdQRdAtq/gsD/KNVV4n+Ssuu
WxcFyPKNIzFTONItaj+CuY0IavdeQXRuwxF+B6wpYJE/OMpXEA29MC/HpeZBoNquBYeaoKRlbEwJ
DIm6uNO5wJOKMPqN5ZprFQFOZ6raYlY+hAhm0sQ2fac+EPyI4NSA5QC9qvNOBqN6avlicuMJT+ub
DgEj8Z+7fNzcbBGXJbLytGMU0gYqZ4yD9c7qB9iaah7s5Aq7KkzrCWA5zspi2C5u
-----END CERTIFICATE-----

SecureTrust CA
==============
-----BEGIN CERTIFICATE-----
MIIDuDCCAqCgAwIBAgIQDPCOXAgWpa1Cf/DrJxhZ0DANBgkqhkiG9w0BAQUFADBIMQswCQYDVQQG
EwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3QgQ29ycG9yYXRpb24xFzAVBgNVBAMTDlNlY3VyZVRy
dXN0IENBMB4XDTA2MTEwNzE5MzExOFoXDTI5MTIzMTE5NDA1NVowSDELMAkGA1UEBhMCVVMxIDAe
BgNVBAoTF1NlY3VyZVRydXN0IENvcnBvcmF0aW9uMRcwFQYDVQQDEw5TZWN1cmVUcnVzdCBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKukgeWVzfX2FI7CT8rU4niVWJxB4Q2ZQCQX
OZEzZum+4YOvYlyJ0fwkW2Gz4BERQRwdbvC4u/jep4G6pkjGnx29vo6pQT64lO0pGtSO0gMdA+9t
DWccV9cGrcrI9f4Or2YlSASWC12juhbDCE/RRvgUXPLIXgGZbf2IzIaowW8xQmxSPmjL8xk037uH
GFaAJsTQ3MBv396gwpEWoGQRS0S8Hvbn+mPeZqx2pHGj7DaUaHp3pLHnDi+BeuK1cobvomuL8A/b
01k/unK8RCSc43Oz969XL0Imnal0ugBS8kvNU3xHCzaFDmapCJcWNFfBZveA4+1wVMeT4C4oFVmH
ursCAwEAAaOBnTCBmjATBgkrBgEEAYI3FAIEBh4EAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQUQjK2FvoE/f5dS3rD/fdMQB1aQ68wNAYDVR0fBC0wKzApoCegJYYj
aHR0cDovL2NybC5zZWN1cmV0cnVzdC5jb20vU1RDQS5jcmwwEAYJKwYBBAGCNxUBBAMCAQAwDQYJ
KoZIhvcNAQEFBQADggEBADDtT0rhWDpSclu1pqNlGKa7UTt36Z3q059c4EVlew3KW+JwULKUBRSu
SceNQQcSc5R+DCMh/bwQf2AQWnL1mA6s7Ll/3XpvXdMc9P+IBWlCqQVxyLesJugutIxq/3HcuLHf
mbx8IVQr5Fiiu1cprp6poxkmD5kuCLDv/WnPmRoJjeOnnyvJNjR7JLN4TJUXpAYmHrZkUjZfYGfZ
nMUFdAvnZyPSCPyI6a6Lf+Ew9Dd+/cYy2i2eRDAwbO4H3tI0/NL/QPZL9GZGBlSm8jIKYyYwa5vR
3ItHuuG51WLQoqD0ZwV4KWMabwTW+MZMo5qxN7SN5ShLHZ4swrhovO0C7jE=
-----END CERTIFICATE-----

Secure Global CA
================
-----BEGIN CERTIFICATE-----
MIIDvDCCAqSgAwIBAgIQB1YipOjUiolN9BPI8PjqpTANBgkqhkiG9w0BAQUFADBKMQswCQYDVQQG
EwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3QgQ29ycG9yYXRpb24xGTAXBgNVBAMTEFNlY3VyZSBH
bG9iYWwgQ0EwHhcNMDYxMTA3MTk0MjI4WhcNMjkxMjMxMTk1MjA2WjBKMQswCQYDVQQGEwJVUzEg
MB4GA1UEChMXU2VjdXJlVHJ1c3QgQ29ycG9yYXRpb24xGTAXBgNVBAMTEFNlY3VyZSBHbG9iYWwg
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvNS7YrGxVaQZx5RNoJLNP2MwhR/jx
YDiJiQPpvepeRlMJ3Fz1Wuj3RSoC6zFh1ykzTM7HfAo3fg+6MpjhHZevj8fcyTiW89sa/FHtaMbQ
bqR8JNGuQsiWUGMu4P51/pinX0kuleM5M2SOHqRfkNJnPLLZ/kG5VacJjnIFHovdRIWCQtBJwB1g
8NEXLJXr9qXBkqPFwqcIYA1gBBCWeZ4WNOaptvolRTnIHmX5k/Wq8VLcmZg9pYYaDDUz+kulBAYV
HDGA76oYa8J719rO+TMg1fW9ajMtgQT7sFzUnKPiXB3jqUJ1XnvUd+85VLrJChgbEplJL4hL/VBi
0XPnj3pDAgMBAAGjgZ0wgZowEwYJKwYBBAGCNxQCBAYeBABDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
EwEB/wQFMAMBAf8wHQYDVR0OBBYEFK9EBMJBfkiD2045AuzshHrmzsmkMDQGA1UdHwQtMCswKaAn
oCWGI2h0dHA6Ly9jcmwuc2VjdXJldHJ1c3QuY29tL1NHQ0EuY3JsMBAGCSsGAQQBgjcVAQQDAgEA
MA0GCSqGSIb3DQEBBQUAA4IBAQBjGghAfaReUw132HquHw0LURYD7xh8yOOvaliTFGCRsoTciE6+
OYo68+aCiV0BN7OrJKQVDpI1WkpEXk5X+nXOH0jOZvQ8QCaSmGwb7iRGDBezUqXbpZGRzzfTb+cn
CDpOGR86p1hcF895P4vkp9MmI50mD1hp/Ed+stCNi5O/KU9DaXR2Z0vPB4zmAve14bRDtUstFJ/5
3CYNv6ZHdAbYiNE6KTCEztI5gGIbqMdXSbxqVVFnFUq+NQfk1XWYN3kwFNspnWzFacxHVaIw98xc
f8LDmBxrThaA63p4ZUWiABqvDA1VZDRIuJK58bRQKfJPIx/abKwfROHdI3hRW8cW
-----END CERTIFICATE-----

COMODO Certification Authority
==============================
-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgIQToEtioJl4AsC7j41AkblPTANBgkqhkiG9w0BAQUFADCBgTELMAkGA1UE
BhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgG
A1UEChMRQ09NT0RPIENBIExpbWl0ZWQxJzAlBgNVBAMTHkNPTU9ETyBDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eTAeFw0wNjEyMDEwMDAwMDBaFw0yOTEyMzEyMzU5NTlaMIGBMQswCQYDVQQGEwJHQjEb
MBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFD
T01PRE8gQ0EgTGltaXRlZDEnMCUGA1UEAxMeQ09NT0RPIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ECLi3LjkRv3UcEbVASY06m/weaKXTuH
+7uIzg3jLz8GlvCiKVCZrts7oVewdFFxze1CkU1B/qnI2GqGd0S7WWaXUF601CxwRM/aN5VCaTww
xHGzUvAhTaHYujl8HJ6jJJ3ygxaYqhZ8Q5sVW7euNJH+1GImGEaaP+vB+fGQV+useg2L23IwambV
4EajcNxo2f8ESIl33rXp+2dtQem8Ob0y2WIC8bGoPW43nOIv4tOiJovGuFVDiOEjPqXSJDlqR6sA
1KGzqSX+DT+nHbrTUcELpNqsOO9VUCQFZUaTNE8tja3G1CEZ0o7KBWFxB3NH5YoZEr0ETc5OnKVI
rLsm9wIDAQABo4GOMIGLMB0GA1UdDgQWBBQLWOWLxkwVN6RAqTCpIb5HNlpW/zAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLmNvbW9k
b2NhLmNvbS9DT01PRE9DZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDANBgkqhkiG9w0BAQUFAAOC
AQEAPpiem/Yb6dc5t3iuHXIYSdOH5EOC6z/JqvWote9VfCFSZfnVDeFs9D6Mk3ORLgLETgdxb8CP
OGEIqB6BCsAvIC9Bi5HcSEW88cbeunZrM8gALTFGTO3nnc+IlP8zwFboJIYmuNg4ON8qa90SzMc/
RxdMosIGlgnW2/4/PEZB31jiVg88O8EckzXZOFKs7sjsLjBOlDW0JB9LeGna8gI4zJVSk/BwJVmc
IGfE7vmLV2H0knZ9P4SNVbfo5azV8fUZVqZa+5Acr5Pr5RzUZ5ddBA6+C4OmF4O5MBKgxTMVBbkN
+8cFduPYSo38NBejxiEovjBFMR7HeL5YYTisO+IBZQ==
-----END CERTIFICATE-----

Network Solutions Certificate Authority
=======================================
-----BEGIN CERTIFICATE-----
MIID5jCCAs6gAwIBAgIQV8szb8JcFuZHFhfjkDFo4DANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQG
EwJVUzEhMB8GA1UEChMYTmV0d29yayBTb2x1dGlvbnMgTC5MLkMuMTAwLgYDVQQDEydOZXR3b3Jr
IFNvbHV0aW9ucyBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDYxMjAxMDAwMDAwWhcNMjkxMjMx
MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYTmV0d29yayBTb2x1dGlvbnMgTC5MLkMu
MTAwLgYDVQQDEydOZXR3b3JrIFNvbHV0aW9ucyBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkvH6SMG3G2I4rC7xGzuAnlt7e+foS0zwzc7MEL7xx
jOWftiJgPl9dzgn/ggwbmlFQGiaJ3dVhXRncEg8tCqJDXRfQNJIg6nPPOCwGJgl6cvf6UDL4wpPT
aaIjzkGxzOTVHzbRijr4jGPiFFlp7Q3Tf2vouAPlT2rlmGNpSAW+Lv8ztumXWWn4Zxmuk2GWRBXT
crA/vGp97Eh/jcOrqnErU2lBUzS1sLnFBgrEsEX1QV1uiUV7PTsmjHTC5dLRfbIR1PtYMiKagMnc
/Qzpf14Dl847ABSHJ3A4qY5usyd2mFHgBeMhqxrVhSI8KbWaFsWAqPS7azCPL0YCorEMIuDTAgMB
AAGjgZcwgZQwHQYDVR0OBBYEFCEwyfsA106Y2oeqKtCnLrFAMadMMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MFIGA1UdHwRLMEkwR6BFoEOGQWh0dHA6Ly9jcmwubmV0c29sc3NsLmNv
bS9OZXR3b3JrU29sdXRpb25zQ2VydGlmaWNhdGVBdXRob3JpdHkuY3JsMA0GCSqGSIb3DQEBBQUA
A4IBAQC7rkvnt1frf6ott3NHhWrB5KUd5Oc86fRZZXe1eltajSU24HqXLjjAV2CDmAaDn7l2em5Q
4LqILPxFzBiwmZVRDuwduIj/h1AcgsLj4DKAv6ALR8jDMe+ZZzKATxcheQxpXN5eNK4CtSbqUN9/
GGUsyfJj4akH/nxxH2szJGoeBfcFaMBqEssuXmHLrijTfsK0ZpEmXzwuJF/LWA/rKOyvEZbz3Htv
wKeI8lN3s2Berq4o2jUsbzRF0ybh3uxbTydrFny9RAQYgrOJeRcQcT16ohZO9QHNpGxlaKFJdlxD
ydi8NmdspZS11My5vWo1ViHe2MPr+8ukYEywVaCge1ey
-----END CERTIFICATE-----

COMODO ECC Certification Authority
==================================
-----BEGIN CERTIFICATE-----
MIICiTCCAg+gAwIBAgIQH0evqmIAcFBUTAGem2OZKjAKBggqhkjOPQQDAzCBhTELMAkGA1UEBhMC
R0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UE
ChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBB
dXRob3JpdHkwHhcNMDgwMzA2MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0Ix
GzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRo
b3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQDR3svdcmCFYX7deSRFtSrYpn1PlILBs5BAH+X
4QokPB0BBO490o0JlwzgdeT6+3eKKvUDYEs2ixYjFq0JcfRK9ChQtP6IHG4/bC8vCVlbpVsLM5ni
wz2J+Wos77LTBumjQjBAMB0GA1UdDgQWBBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjEA7wNbeqy3eApyt4jf/7VG
FAkK+qDmfQjGGoe9GKhzvSbKYAydzpmfz1wPMOG+FDHqAjAU9JM8SaczepBGR7NjfRObTrdvGDeA
U/7dIOA1mjbRxwG55tzd8/8dLDoWV9mSOdY=
-----END CERTIFICATE-----

Certigna
========
-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIJAP7c4wEPyUj/MA0GCSqGSIb3DQEBBQUAMDQxCzAJBgNVBAYTAkZSMRIw
EAYDVQQKDAlEaGlteW90aXMxETAPBgNVBAMMCENlcnRpZ25hMB4XDTA3MDYyOTE1MTMwNVoXDTI3
MDYyOTE1MTMwNVowNDELMAkGA1UEBhMCRlIxEjAQBgNVBAoMCURoaW15b3RpczERMA8GA1UEAwwI
Q2VydGlnbmEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIaPHJ1tazNHUmgh7stL7q
XOEm7RFHYeGifBZ4QCHkYJ5ayGPhxLGWkv8YbWkj4Sti993iNi+RB7lIzw7sebYs5zRLcAglozyH
GxnygQcPOJAZ0xH+hrTy0V4eHpbNgGzOOzGTtvKg0KmVEn2lmsxryIRWijOp5yIVUxbwzBfsV1/p
ogqYCd7jX5xv3EjjhQsVWqa6n6xI4wmy9/Qy3l40vhx4XUJbzg4ij02Q130yGLMLLGq/jj8UEYkg
DncUtT2UCIf3JR7VsmAA7G8qKCVuKj4YYxclPz5EIBb2JsglrgVKtOdjLPOMFlN+XPsRGgjBRmKf
Irjxwo1p3Po6WAbfAgMBAAGjgbwwgbkwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUGu3+QTmQ
tCRZvgHyUtVF9lo53BEwZAYDVR0jBF0wW4AUGu3+QTmQtCRZvgHyUtVF9lo53BGhOKQ2MDQxCzAJ
BgNVBAYTAkZSMRIwEAYDVQQKDAlEaGlteW90aXMxETAPBgNVBAMMCENlcnRpZ25hggkA/tzjAQ/J
SP8wDgYDVR0PAQH/BAQDAgEGMBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG9w0BAQUFAAOCAQEA
hQMeknH2Qq/ho2Ge6/PAD/Kl1NqV5ta+aDY9fm4fTIrv0Q8hbV6lUmPOEvjvKtpv6zf+EwLHyzs+
ImvaYS5/1HI93TDhHkxAGYwP15zRgzB7mFncfca5DClMoTOi62c6ZYTTluLtdkVwj7Ur3vkj1klu
PBS1xp81HlDQwY9qcEQCYsuuHWhBp6pX6FOqB9IG9tUUBguRA3UsbHK1YZWaDYu5Def131TN3ubY
1gkIl2PlwS6wt0QmwCbAr1UwnjvVNioZBPRcHv/PLLf/0P2HQBHVESO7SMAhqaQoLf0V+LBOK/Qw
WyH8EZE0vkHve52Xdf+XlcCWWC/qu0bXu+TZLg==
-----END CERTIFICATE-----

Cybertrust Global Root
======================
-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgILBAAAAAABD4WqLUgwDQYJKoZIhvcNAQEFBQAwOzEYMBYGA1UEChMPQ3li
ZXJ0cnVzdCwgSW5jMR8wHQYDVQQDExZDeWJlcnRydXN0IEdsb2JhbCBSb290MB4XDTA2MTIxNTA4
MDAwMFoXDTIxMTIxNTA4MDAwMFowOzEYMBYGA1UEChMPQ3liZXJ0cnVzdCwgSW5jMR8wHQYDVQQD
ExZDeWJlcnRydXN0IEdsb2JhbCBSb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
+Mi8vRRQZhP/8NN57CPytxrHjoXxEnOmGaoQ25yiZXRadz5RfVb23CO21O1fWLE3TdVJDm71aofW
0ozSJ8bi/zafmGWgE07GKmSb1ZASzxQG9Dvj1Ci+6A74q05IlG2OlTEQXO2iLb3VOm2yHLtgwEZL
AfVJrn5GitB0jaEMAs7u/OePuGtm839EAL9mJRQr3RAwHQeWP032a7iPt3sMpTjr3kfb1V05/Iin
89cqdPHoWqI7n1C6poxFNcJQZZXcY4Lv3b93TZxiyWNzFtApD0mpSPCzqrdsxacwOUBdrsTiXSZT
8M4cIwhhqJQZugRiQOwfOHB3EgZxpzAYXSUnpQIDAQABo4GlMIGiMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS2CHsNesysIEyGVjJez6tuhS1wVzA/BgNVHR8EODA2
MDSgMqAwhi5odHRwOi8vd3d3Mi5wdWJsaWMtdHJ1c3QuY29tL2NybC9jdC9jdHJvb3QuY3JsMB8G
A1UdIwQYMBaAFLYIew16zKwgTIZWMl7Pq26FLXBXMA0GCSqGSIb3DQEBBQUAA4IBAQBW7wojoFRO
lZfJ+InaRcHUowAl9B8Tq7ejhVhpwjCt2BWKLePJzYFa+HMjWqd8BfP9IjsO0QbE2zZMcwSO5bAi
5MXzLqXZI+O4Tkogp24CJJ8iYGd7ix1yCcUxXOl5n4BHPa2hCwcUPUf/A2kaDAtE52Mlp3+yybh2
hO0j9n0Hq0V+09+zv+mKts2oomcrUtW3ZfA5TGOgkXmTUg9U3YO7n9GPp1Nzw8v/MOx8BLjYRB+T
X3EJIrduPuocA06dGiBh+4E37F78CkWr1+cXVdCg6mCbpvbjjFspwgZgFJ0tl0ypkxWdYcQBX0jW
WL1WMRJOEcgh4LMRkWXbtKaIOM5V
-----END CERTIFICATE-----

ePKI Root Certification Authority
=================================
-----BEGIN CERTIFICATE-----
MIIFsDCCA5igAwIBAgIQFci9ZUdcr7iXAF7kBtK8nTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQG
EwJUVzEjMCEGA1UECgwaQ2h1bmdod2EgVGVsZWNvbSBDby4sIEx0ZC4xKjAoBgNVBAsMIWVQS0kg
Um9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNDEyMjAwMjMxMjdaFw0zNDEyMjAwMjMx
MjdaMF4xCzAJBgNVBAYTAlRXMSMwIQYDVQQKDBpDaHVuZ2h3YSBUZWxlY29tIENvLiwgTHRkLjEq
MCgGA1UECwwhZVBLSSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEA4SUP7o3biDN1Z82tH306Tm2d0y8U82N0ywEhajfqhFAHSyZbCUNs
IZ5qyNUD9WBpj8zwIuQf5/dqIjG3LBXy4P4AakP/h2XGtRrBp0xtInAhijHyl3SJCRImHJ7K2RKi
lTza6We/CKBk49ZCt0Xvl/T29de1ShUCWH2YWEtgvM3XDZoTM1PRYfl61dd4s5oz9wCGzh1NlDiv
qOx4UXCKXBCDUSH3ET00hl7lSM2XgYI1TBnsZfZrxQWh7kcT1rMhJ5QQCtkkO7q+RBNGMD+XPNjX
12ruOzjjK9SXDrkb5wdJfzcq+Xd4z1TtW0ado4AOkUPB1ltfFLqfpo0kR0BZv3I4sjZsN/+Z0V0O
WQqraffAsgRFelQArr5T9rXn4fg8ozHSqf4hUmTFpmfwdQcGlBSBVcYn5AGPF8Fqcde+S/uUWH1+
ETOxQvdibBjWzwloPn9s9h6PYq2lY9sJpx8iQkEeb5mKPtf5P0B6ebClAZLSnT0IFaUQAS2zMnao
lQ2zepr7BxB4EW/hj8e6DyUadCrlHJhBmd8hh+iVBmoKs2pHdmX2Os+PYhcZewoozRrSgx4hxyy/
vv9haLdnG7t4TY3OZ+XkwY63I2binZB1NJipNiuKmpS5nezMirH4JYlcWrYvjB9teSSnUmjDhDXi
Zo1jDiVN1Rmy5nk3pyKdVDECAwEAAaNqMGgwHQYDVR0OBBYEFB4M97Zn8uGSJglFwFU5Lnc/Qkqi
MAwGA1UdEwQFMAMBAf8wOQYEZyoHAAQxMC8wLQIBADAJBgUrDgMCGgUAMAcGBWcqAwAABBRFsMLH
ClZ87lt4DJX5GFPBphzYEDANBgkqhkiG9w0BAQUFAAOCAgEACbODU1kBPpVJufGBuvl2ICO1J2B0
1GqZNF5sAFPZn/KmsSQHRGoqxqWOeBLoR9lYGxMqXnmbnwoqZ6YlPwZpVnPDimZI+ymBV3QGypzq
KOg4ZyYr8dW1P2WT+DZdjo2NQCCHGervJ8A9tDkPJXtoUHRVnAxZfVo9QZQlUgjgRywVMRnVvwdV
xrsStZf0X4OFunHB2WyBEXYKCrC/gpf36j36+uwtqSiUO1bd0lEursC9CBWMd1I0ltabrNMdjmEP
NXubrjlpC2JgQCA2j6/7Nu4tCEoduL+bXPjqpRugc6bY+G7gMwRfaKonh+3ZwZCc7b3jajWvY9+r
GNm65ulK6lCKD2GTHuItGeIwlDWSXQ62B68ZgI9HkFFLLk3dheLSClIKF5r8GrBQAuUBo2M3IUxE
xJtRmREOc5wGj1QupyheRDmHVi03vYVElOEMSyycw5KFNGHLD7ibSkNS/jQ6fbjpKdx2qcgw+BRx
gMYeNkh0IkFch4LoGHGLQYlE535YW6i4jRPpp2zDR+2zGp1iro2C6pSe3VkQw63d4k3jMdXH7Ojy
sP6SHhYKGvzZ8/gntsm+HbRsZJB/9OTEW9c3rkIO3aQab3yIVMUWbuF6aC74Or8NpDyJO3inTmOD
BCEIZ43ygknQW/2xzQ+DhNQ+IIX3Sj0rnP0qCglN6oH4EZw=
-----END CERTIFICATE-----

certSIGN ROOT CA
================
-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIGIAYFFnACMA0GCSqGSIb3DQEBBQUAMDsxCzAJBgNVBAYTAlJPMREwDwYD
VQQKEwhjZXJ0U0lHTjEZMBcGA1UECxMQY2VydFNJR04gUk9PVCBDQTAeFw0wNjA3MDQxNzIwMDRa
Fw0zMTA3MDQxNzIwMDRaMDsxCzAJBgNVBAYTAlJPMREwDwYDVQQKEwhjZXJ0U0lHTjEZMBcGA1UE
CxMQY2VydFNJR04gUk9PVCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALczuX7I
JUqOtdu0KBuqV5Do0SLTZLrTk+jUrIZhQGpgV2hUhE28alQCBf/fm5oqrl0Hj0rDKH/v+yv6efHH
rfAQUySQi2bJqIirr1qjAOm+ukbuW3N7LBeCgV5iLKECZbO9xSsAfsT8AzNXDe3i+s5dRdY4zTW2
ssHQnIFKquSyAVwdj1+ZxLGt24gh65AIgoDzMKND5pCCrlUoSe1b16kQOA7+j0xbm0bqQfWwCHTD
0IgztnzXdN/chNFDDnU5oSVAKOp4yw4sLjmdjItuFhwvJoIQ4uNllAoEwF73XVv4EOLQunpL+943
AAAaWyjj0pxzPjKHmKHJUS/X3qwzs08CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAcYwHQYDVR0OBBYEFOCMm9slSbPxfIbWskKHC9BroNnkMA0GCSqGSIb3DQEBBQUAA4IB
AQA+0hyJLjX8+HXd5n9liPRyTMks1zJO890ZeUe9jjtbkw9QSSQTaxQGcu8J06Gh40CEyecYMnQ8
SG4Pn0vU9x7Tk4ZkVJdjclDVVc/6IJMCopvDI5NOFlV2oHB5bc0hH88vLbwZ44gx+FkagQnIl6Z0
x2DEW8xXjrJ1/RsCCdtZb3KTafcxQdaIOL+Hsr0Wefmq5L6IJd1hJyMctTEHBDa0GpC9oHRxUIlt
vBTjD4au8as+x6AJzKNI0eDbZOeStc+vckNwi/nDhDwTqn6Sm1dTk/pwwpEOMfmbZ13pljheX7Nz
TogVZ96edhBiIL5VaZVDADlN9u6wWk5JRFRYX0KD
-----END CERTIFICATE-----

GeoTrust Primary Certification Authority - G2
=============================================
-----BEGIN CERTIFICATE-----
MIICrjCCAjWgAwIBAgIQPLL0SAoA4v7rJDteYD7DazAKBggqhkjOPQQDAzCBmDELMAkGA1UEBhMC
VVMxFjAUBgNVBAoTDUdlb1RydXN0IEluYy4xOTA3BgNVBAsTMChjKSAyMDA3IEdlb1RydXN0IElu
Yy4gLSBGb3IgYXV0aG9yaXplZCB1c2Ugb25seTE2MDQGA1UEAxMtR2VvVHJ1c3QgUHJpbWFyeSBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEcyMB4XDTA3MTEwNTAwMDAwMFoXDTM4MDExODIzNTk1
OVowgZgxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMTkwNwYDVQQLEzAoYykg
MjAwNyBHZW9UcnVzdCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxNjA0BgNVBAMTLUdl
b1RydXN0IFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHMjB2MBAGByqGSM49AgEG
BSuBBAAiA2IABBWx6P0DFUPlrOuHNxFi79KDNlJ9RVcLSo17VDs6bl8VAsBQps8lL33KSLjHUGMc
KiEIfJo22Av+0SbFWDEwKCXzXV2juLaltJLtbCyf691DiaI8S0iRHVDsJt/WYC69IaNCMEAwDwYD
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFBVfNVdRVfslsq0DafwBo/q+
EVXVMAoGCCqGSM49BAMDA2cAMGQCMGSWWaboCd6LuvpaiIjwH5HTRqjySkwCY/tsXzjbLkGTqQ7m
ndwxHLKgpxgceeHHNgIwOlavmnRs9vuD4DPTCF+hnMJbn0bWtsuRBmOiBuczrD6ogRLQy7rQkgu2
npaqBA+K
-----END CERTIFICATE-----

VeriSign Universal Root Certification Authority
===============================================
-----BEGIN CERTIFICATE-----
MIIEuTCCA6GgAwIBAgIQQBrEZCGzEyEDDrvkEhrFHTANBgkqhkiG9w0BAQsFADCBvTELMAkGA1UE
BhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBO
ZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBWZXJpU2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVk
IHVzZSBvbmx5MTgwNgYDVQQDEy9WZXJpU2lnbiBVbml2ZXJzYWwgUm9vdCBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTAeFw0wODA0MDIwMDAwMDBaFw0zNzEyMDEyMzU5NTlaMIG9MQswCQYDVQQGEwJV
UzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdv
cmsxOjA4BgNVBAsTMShjKSAyMDA4IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNl
IG9ubHkxODA2BgNVBAMTL1ZlcmlTaWduIFVuaXZlcnNhbCBSb290IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx2E3XrEBNNti1xWb/1hajCMj
1mCOkdeQmIN65lgZOIzF9uVkhbSicfvtvbnazU0AtMgtc6XHaXGVHzk8skQHnOgO+k1KxCHfKWGP
MiJhgsWHH26MfF8WIFFE0XBPV+rjHOPMee5Y2A7Cs0WTwCznmhcrewA3ekEzeOEz4vMQGn+HLL72
9fdC4uW/h2KJXwBL38Xd5HVEMkE6HnFuacsLdUYI0crSK5XQz/u5QGtkjFdN/BMReYTtXlT2NJ8I
AfMQJQYXStrxHXpma5hgZqTZ79IugvHw7wnqRMkVauIDbjPTrJ9VAMf2CGqUuV/c4DPxhGD5WycR
tPwW8rtWaoAljQIDAQABo4GyMIGvMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMG0G
CCsGAQUFBwEMBGEwX6FdoFswWTBXMFUWCWltYWdlL2dpZjAhMB8wBwYFKw4DAhoEFI/l0xqGrI2O
a8PPgGrUSBgsexkuMCUWI2h0dHA6Ly9sb2dvLnZlcmlzaWduLmNvbS92c2xvZ28uZ2lmMB0GA1Ud
DgQWBBS2d/ppSEefUxLVwuoHMnYH0ZcHGTANBgkqhkiG9w0BAQsFAAOCAQEASvj4sAPmLGd75JR3
Y8xuTPl9Dg3cyLk1uXBPY/ok+myDjEedO2Pzmvl2MpWRsXe8rJq+seQxIcaBlVZaDrHC1LGmWazx
Y8u4TB1ZkErvkBYoH1quEPuBUDgMbMzxPcP1Y+Oz4yHJJDnp/RVmRvQbEdBNc6N9Rvk97ahfYtTx
P/jgdFcrGJ2BtMQo2pSXpXDrrB2+BxHw1dvd5Yzw1TKwg+ZX4o+/vqGqvz0dtdQ46tewXDpPaj+P
wGZsY6rp2aQW9IHRlRQOfc2VNNnSj3BzgXucfr2YYdhFh5iQxeuGMMY1v/D/w1WIg0vvBZIGcfK4
mJO37M2CYfE45k+XmCpajQ==
-----END CERTIFICATE-----

NetLock Arany (Class Gold) Főtanúsítvány
========================================
-----BEGIN CERTIFICATE-----
MIIEFTCCAv2gAwIBAgIGSUEs5AAQMA0GCSqGSIb3DQEBCwUAMIGnMQswCQYDVQQGEwJIVTERMA8G
A1UEBwwIQnVkYXBlc3QxFTATBgNVBAoMDE5ldExvY2sgS2Z0LjE3MDUGA1UECwwuVGFuw7pzw610
dsOhbnlraWFkw7NrIChDZXJ0aWZpY2F0aW9uIFNlcnZpY2VzKTE1MDMGA1UEAwwsTmV0TG9jayBB
cmFueSAoQ2xhc3MgR29sZCkgRsWRdGFuw7pzw610dsOhbnkwHhcNMDgxMjExMTUwODIxWhcNMjgx
MjA2MTUwODIxWjCBpzELMAkGA1UEBhMCSFUxETAPBgNVBAcMCEJ1ZGFwZXN0MRUwEwYDVQQKDAxO
ZXRMb2NrIEtmdC4xNzA1BgNVBAsMLlRhbsO6c8OtdHbDoW55a2lhZMOzayAoQ2VydGlmaWNhdGlv
biBTZXJ2aWNlcykxNTAzBgNVBAMMLE5ldExvY2sgQXJhbnkgKENsYXNzIEdvbGQpIEbFkXRhbsO6
c8OtdHbDoW55MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxCRec75LbRTDofTjl5Bu
0jBFHjzuZ9lk4BqKf8owyoPjIMHj9DrTlF8afFttvzBPhCf2nx9JvMaZCpDyD/V/Q4Q3Y1GLeqVw
/HpYzY6b7cNGbIRwXdrzAZAj/E4wqX7hJ2Pn7WQ8oLjJM2P+FpD/sLj916jAwJRDC7bVWaaeVtAk
H3B5r9s5VA1lddkVQZQBr17s9o3x/61k/iCa11zr/qYfCGSji3ZVrR47KGAuhyXoqq8fxmRGILdw
fzzeSNuWU7c5d+Qa4scWhHaXWy+7GRWF+GmF9ZmnqfI0p6m2pgP8b4Y9VHx2BJtr+UBdADTHLpl1
neWIA6pN+APSQnbAGwIDAKiLo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEEMA4GA1UdDwEB/wQEAwIB
BjAdBgNVHQ4EFgQUzPpnk/C2uNClwB7zU/2MU9+D15YwDQYJKoZIhvcNAQELBQADggEBAKt/7hwW
qZw8UQCgwBEIBaeZ5m8BiFRhbvG5GK1Krf6BQCOUL/t1fC8oS2IkgYIL9WHxHG64YTjrgfpioTta
YtOUZcTh5m2C+C8lcLIhJsFyUR+MLMOEkMNaj7rP9KdlpeuY0fsFskZ1FSNqb4VjMIDw1Z4fKRzC
bLBQWV2QWzuoDTDPv31/zvGdg73JRm4gpvlhUbohL3u+pRVjodSVh/GeufOJ8z2FuLjbvrW5Kfna
NwUASZQDhETnv0Mxz3WLJdH0pmT1kvarBes96aULNmLazAZfNou2XjG4Kvte9nHfRCaexOYNkbQu
dZWAUWpLMKawYqGT8ZvYzsRjdT9ZR7E=
-----END CERTIFICATE-----

Hongkong Post Root CA 1
=======================
-----BEGIN CERTIFICATE-----
MIIDMDCCAhigAwIBAgICA+gwDQYJKoZIhvcNAQEFBQAwRzELMAkGA1UEBhMCSEsxFjAUBgNVBAoT
DUhvbmdrb25nIFBvc3QxIDAeBgNVBAMTF0hvbmdrb25nIFBvc3QgUm9vdCBDQSAxMB4XDTAzMDUx
NTA1MTMxNFoXDTIzMDUxNTA0NTIyOVowRzELMAkGA1UEBhMCSEsxFjAUBgNVBAoTDUhvbmdrb25n
IFBvc3QxIDAeBgNVBAMTF0hvbmdrb25nIFBvc3QgUm9vdCBDQSAxMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEArP84tulmAknjorThkPlAj3n54r15/gK97iSSHSL22oVyaf7XPwnU3ZG1
ApzQjVrhVcNQhrkpJsLj2aDxaQMoIIBFIi1WpztUlVYiWR8o3x8gPW2iNr4joLFutbEnPzlTCeqr
auh0ssJlXI6/fMN4hM2eFvz1Lk8gKgifd/PFHsSaUmYeSF7jEAaPIpjhZY4bXSNmO7ilMlHIhqqh
qZ5/dpTCpmy3QfDVyAY45tQM4vM7TG1QjMSDJ8EThFk9nnV0ttgCXjqQesBCNnLsak3c78QA3xMY
V18meMjWCnl3v/evt3a5pQuEF10Q6m/hq5URX208o1xNg1vysxmKgIsLhwIDAQABoyYwJDASBgNV
HRMBAf8ECDAGAQH/AgEDMA4GA1UdDwEB/wQEAwIBxjANBgkqhkiG9w0BAQUFAAOCAQEADkbVPK7i
h9legYsCmEEIjEy82tvuJxuC52pF7BaLT4Wg87JwvVqWuspube5Gi27nKi6Wsxkz67SfqLI37pio
l7Yutmcn1KZJ/RyTZXaeQi/cImyaT/JaFTmxcdcrUehtHJjA2Sr0oYJ71clBoiMBdDhViw+5Lmei
IAQ32pwL0xch4I+XeTRvhEgCIDMb5jREn5Fw9IBehEPCKdJsEhTkYY2sEJCehFC78JZvRZ+K88ps
T/oROhUVRsPNH4NbLUES7VBnQRM9IauUiqpOfMGx+6fWtScvl6tu4B3i0RwsH0Ti/L6RoZz71ilT
c4afU9hDDl3WY4JxHYB0yvbiAmvZWg==
-----END CERTIFICATE-----

SecureSign RootCA11
===================
-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIBATANBgkqhkiG9w0BAQUFADBYMQswCQYDVQQGEwJKUDErMCkGA1UEChMi
SmFwYW4gQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcywgSW5jLjEcMBoGA1UEAxMTU2VjdXJlU2lnbiBS
b290Q0ExMTAeFw0wOTA0MDgwNDU2NDdaFw0yOTA0MDgwNDU2NDdaMFgxCzAJBgNVBAYTAkpQMSsw
KQYDVQQKEyJKYXBhbiBDZXJ0aWZpY2F0aW9uIFNlcnZpY2VzLCBJbmMuMRwwGgYDVQQDExNTZWN1
cmVTaWduIFJvb3RDQTExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA/XeqpRyQBTvL
TJszi1oURaTnkBbR31fSIRCkF/3frNYfp+TbfPfs37gD2pRY/V1yfIw/XwFndBWW4wI8h9uuywGO
wvNmxoVF9ALGOrVisq/6nL+k5tSAMJjzDbaTj6nU2DbysPyKyiyhFTOVMdrAG/LuYpmGYz+/3ZMq
g6h2uRMft85OQoWPIucuGvKVCbIFtUROd6EgvanyTgp9UK31BQ1FT0Zx/Sg+U/sE2C3XZR1KG/rP
O7AxmjVuyIsG0wCR8pQIZUyxNAYAeoni8McDWc/V1uinMrPmmECGxc0nEovMe863ETxiYAcjPitA
bpSACW22s293bzUIUPsCh8U+iQIDAQABo0IwQDAdBgNVHQ4EFgQUW/hNT7KlhtQ60vFjmqC+CfZX
t94wDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAKCh
OBZmLqdWHyGcBvod7bkixTgm2E5P7KN/ed5GIaGHd48HCJqypMWvDzKYC3xmKbabfSVSSUOrTC4r
bnpwrxYO4wJs+0LmGJ1F2FXI6Dvd5+H0LgscNFxsWEr7jIhQX5Ucv+2rIrVls4W6ng+4reV6G4pQ
Oh29Dbx7VFALuUKvVaAYga1lme++5Jy/xIWrQbJUb9wlze144o4MjQlJ3WN7WmmWAiGovVJZ6X01
y8hSyn+B/tlr0/cR7SXf+Of5pPpyl4RTDaXQMhhRdlkUbA/r7F+AjHVDg8OFmP9Mni0N5HeDk061
lgeLKBObjBmNQSdJQO7e5iNEOdyhIta6A/I=
-----END CERTIFICATE-----

Microsec e-Szigno Root CA 2009
==============================
-----BEGIN CERTIFICATE-----
MIIECjCCAvKgAwIBAgIJAMJ+QwRORz8ZMA0GCSqGSIb3DQEBCwUAMIGCMQswCQYDVQQGEwJIVTER
MA8GA1UEBwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xJzAlBgNVBAMMHk1pY3Jv
c2VjIGUtU3ppZ25vIFJvb3QgQ0EgMjAwOTEfMB0GCSqGSIb3DQEJARYQaW5mb0BlLXN6aWduby5o
dTAeFw0wOTA2MTYxMTMwMThaFw0yOTEyMzAxMTMwMThaMIGCMQswCQYDVQQGEwJIVTERMA8GA1UE
BwwIQnVkYXBlc3QxFjAUBgNVBAoMDU1pY3Jvc2VjIEx0ZC4xJzAlBgNVBAMMHk1pY3Jvc2VjIGUt
U3ppZ25vIFJvb3QgQ0EgMjAwOTEfMB0GCSqGSIb3DQEJARYQaW5mb0BlLXN6aWduby5odTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOn4j/NjrdqG2KfgQvvPkd6mJviZpWNwrZuuyjNA
fW2WbqEORO7hE52UQlKavXWFdCyoDh2Tthi3jCyoz/tccbna7P7ofo/kLx2yqHWH2Leh5TvPmUpG
0IMZfcChEhyVbUr02MelTTMuhTlAdX4UfIASmFDHQWe4oIBhVKZsTh/gnQ4H6cm6M+f+wFUoLAKA
pxn1ntxVUwOXewdI/5n7N4okxFnMUBBjjqqpGrCEGob5X7uxUG6k0QrM1XF+H6cbfPVTbiJfyyvm
1HxdrtbCxkzlBQHZ7Vf8wSN5/PrIJIOV87VqUQHQd9bpEqH5GoP7ghu5sJf0dgYzQ0mg/wu1+rUC
AwEAAaOBgDB+MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTLD8bf
QkPMPcu1SCOhGnqmKrs0aDAfBgNVHSMEGDAWgBTLD8bfQkPMPcu1SCOhGnqmKrs0aDAbBgNVHREE
FDASgRBpbmZvQGUtc3ppZ25vLmh1MA0GCSqGSIb3DQEBCwUAA4IBAQDJ0Q5eLtXMs3w+y/w9/w0o
lZMEyL/azXm4Q5DwpL7v8u8hmLzU1F0G9u5C7DBsoKqpyvGvivo/C3NqPuouQH4frlRheesuCDfX
I/OMn74dseGkddug4lQUsbocKaQY9hK6ohQU4zE1yED/t+AFdlfBHFny+L/k7SViXITwfn4fs775
tyERzAMBVnCnEJIeGzSBHq2cGsMEPO0CYdYeBvNfOofyK/FFh+U9rNHHV4S9a67c2Pm2G2JwCz02
yULyMtd6YebS2z3PyKnJm9zbWETXbzivf3jTo60adbocwTZ8jx5tHMN1Rq41Bab2XD0h7lbwyYIi
LXpUq3DDfSJlgnCW
-----END CERTIFICATE-----

GlobalSign Root CA - R3
=======================
-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xv
YmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2Jh
bFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxT
aWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2ln
bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWt
iHL8RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ
0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR5Z2KYVc3
rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjl
OCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2
xmmFghcCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
FI/wS3+oLkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZURUm7
lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMpjjM5RcOO5LlXbKr8
EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK6fBdRoyV3XpYKBovHd7NADdBj+1E
bddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQXmcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18
YIvDQVETI53O9zJrlAGomecsMx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7r
kpeDMdmztcpHWD9f
-----END CERTIFICATE-----

Autoridad de Certificacion Firmaprofesional CIF A62634068
=========================================================
-----BEGIN CERTIFICATE-----
MIIGFDCCA/ygAwIBAgIIU+w77vuySF8wDQYJKoZIhvcNAQEFBQAwUTELMAkGA1UEBhMCRVMxQjBA
BgNVBAMMOUF1dG9yaWRhZCBkZSBDZXJ0aWZpY2FjaW9uIEZpcm1hcHJvZmVzaW9uYWwgQ0lGIEE2
MjYzNDA2ODAeFw0wOTA1MjAwODM4MTVaFw0zMDEyMzEwODM4MTVaMFExCzAJBgNVBAYTAkVTMUIw
QAYDVQQDDDlBdXRvcmlkYWQgZGUgQ2VydGlmaWNhY2lvbiBGaXJtYXByb2Zlc2lvbmFsIENJRiBB
NjI2MzQwNjgwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDKlmuO6vj78aI14H9M2uDD
Utd9thDIAl6zQyrET2qyyhxdKJp4ERppWVevtSBC5IsP5t9bpgOSL/UR5GLXMnE42QQMcas9UX4P
B99jBVzpv5RvwSmCwLTaUbDBPLutN0pcyvFLNg4kq7/DhHf9qFD0sefGL9ItWY16Ck6WaVICqjaY
7Pz6FIMMNx/Jkjd/14Et5cS54D40/mf0PmbR0/RAz15iNA9wBj4gGFrO93IbJWyTdBSTo3OxDqqH
ECNZXyAFGUftaI6SEspd/NYrspI8IM/hX68gvqB2f3bl7BqGYTM+53u0P6APjqK5am+5hyZvQWyI
plD9amML9ZMWGxmPsu2bm8mQ9QEM3xk9Dz44I8kvjwzRAv4bVdZO0I08r0+k8/6vKtMFnXkIoctX
MbScyJCyZ/QYFpM6/EfY0XiWMR+6KwxfXZmtY4laJCB22N/9q06mIqqdXuYnin1oKaPnirjaEbsX
LZmdEyRG98Xi2J+Of8ePdG1asuhy9azuJBCtLxTa/y2aRnFHvkLfuwHb9H/TKI8xWVvTyQKmtFLK
bpf7Q8UIJm+K9Lv9nyiqDdVF8xM6HdjAeI9BZzwelGSuewvF6NkBiDkal4ZkQdU7hwxu+g/GvUgU
vzlN1J5Bto+WHWOWk9mVBngxaJ43BjuAiUVhOSPHG0SjFeUc+JIwuwIDAQABo4HvMIHsMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRlzeurNR4APn7VdMActHNH
DhpkLzCBpgYDVR0gBIGeMIGbMIGYBgRVHSAAMIGPMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmZp
cm1hcHJvZmVzaW9uYWwuY29tL2NwczBcBggrBgEFBQcCAjBQHk4AUABhAHMAZQBvACAAZABlACAA
bABhACAAQgBvAG4AYQBuAG8AdgBhACAANAA3ACAAQgBhAHIAYwBlAGwAbwBuAGEAIAAwADgAMAAx
ADcwDQYJKoZIhvcNAQEFBQADggIBABd9oPm03cXF661LJLWhAqvdpYhKsg9VSytXjDvlMd3+xDLx
51tkljYyGOylMnfX40S2wBEqgLk9am58m9Ot/MPWo+ZkKXzR4Tgegiv/J2Wv+xYVxC5xhOW1//qk
R71kMrv2JYSiJ0L1ILDCExARzRAVukKQKtJE4ZYm6zFIEv0q2skGz3QeqUvVhyj5eTSSPi5E6PaP
T481PyWzOdxjKpBrIF/EUhJOlywqrJ2X3kjyo2bbwtKDlaZmp54lD+kLM5FlClrD2VQS3a/DTg4f
Jl4N3LON7NWBcN7STyQF82xO9UxJZo3R/9ILJUFI/lGExkKvgATP0H5kSeTy36LssUzAKh3ntLFl
osS88Zj0qnAHY7S42jtM+kAiMFsRpvAFDsYCA0irhpuF3dvd6qJ2gHN99ZwExEWN57kci57q13XR
crHedUTnQn3iV2t93Jm8PYMo6oCTjcVMZcFwgbg4/EMxsvYDNEeyrPsiBsse3RdHHF9mudMaotoR
saS8I8nkvof/uZS2+F0gStRf571oe2XyFR7SOqkt6dhrJKyXWERHrVkY8SFlcN7ONGCoQPHzPKTD
KCOM/iczQ0CgFzzr6juwcqajuUpLXhZI9LK8yIySxZ2frHI2vDSANGupi5LAuBft7HZT9SQBjLMi
6Et8Vcad+qMUu2WFbm5PEn4KPJ2V
-----END CERTIFICATE-----

Izenpe.com
==========
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----

Chambers of Commerce Root - 2008
================================
-----BEGIN CERTIFICATE-----
MIIHTzCCBTegAwIBAgIJAKPaQn6ksa7aMA0GCSqGSIb3DQEBBQUAMIGuMQswCQYDVQQGEwJFVTFD
MEEGA1UEBxM6TWFkcmlkIChzZWUgY3VycmVudCBhZGRyZXNzIGF0IHd3dy5jYW1lcmZpcm1hLmNv
bS9hZGRyZXNzKTESMBAGA1UEBRMJQTgyNzQzMjg3MRswGQYDVQQKExJBQyBDYW1lcmZpcm1hIFMu
QS4xKTAnBgNVBAMTIENoYW1iZXJzIG9mIENvbW1lcmNlIFJvb3QgLSAyMDA4MB4XDTA4MDgwMTEy
Mjk1MFoXDTM4MDczMTEyMjk1MFowga4xCzAJBgNVBAYTAkVVMUMwQQYDVQQHEzpNYWRyaWQgKHNl
ZSBjdXJyZW50IGFkZHJlc3MgYXQgd3d3LmNhbWVyZmlybWEuY29tL2FkZHJlc3MpMRIwEAYDVQQF
EwlBODI3NDMyODcxGzAZBgNVBAoTEkFDIENhbWVyZmlybWEgUy5BLjEpMCcGA1UEAxMgQ2hhbWJl
cnMgb2YgQ29tbWVyY2UgUm9vdCAtIDIwMDgwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
AQCvAMtwNyuAWko6bHiUfaN/Gh/2NdW928sNRHI+JrKQUrpjOyhYb6WzbZSm891kDFX29ufyIiKA
XuFixrYp4YFs8r/lfTJqVKAyGVn+H4vXPWCGhSRv4xGzdz4gljUha7MI2XAuZPeEklPWDrCQiorj
h40G072QDuKZoRuGDtqaCrsLYVAGUvGef3bsyw/QHg3PmTA9HMRFEFis1tPo1+XqxQEHd9ZR5gN/
ikilTWh1uem8nk4ZcfUyS5xtYBkL+8ydddy/Js2Pk3g5eXNeJQ7KXOt3EgfLZEFHcpOrUMPrCXZk
NNI5t3YRCQ12RcSprj1qr7V9ZS+UWBDsXHyvfuK2GNnQm05aSd+pZgvMPMZ4fKecHePOjlO+Bd5g
D2vlGts/4+EhySnB8esHnFIbAURRPHsl18TlUlRdJQfKFiC4reRB7noI/plvg6aRArBsNlVq5331
lubKgdaX8ZSD6e2wsWsSaR6s+12pxZjptFtYer49okQ6Y1nUCyXeG0+95QGezdIp1Z8XGQpvvwyQ
0wlf2eOKNcx5Wk0ZN5K3xMGtr/R5JJqyAQuxr1yW84Ay+1w9mPGgP0revq+ULtlVmhduYJ1jbLhj
ya6BXBg14JC7vjxPNyK5fuvPnnchpj04gftI2jE9K+OJ9dC1vX7gUMQSibMjmhAxhduub+84Mxh2
EQIDAQABo4IBbDCCAWgwEgYDVR0TAQH/BAgwBgEB/wIBDDAdBgNVHQ4EFgQU+SSsD7K1+HnA+mCI
G8TZTQKeFxkwgeMGA1UdIwSB2zCB2IAU+SSsD7K1+HnA+mCIG8TZTQKeFxmhgbSkgbEwga4xCzAJ
BgNVBAYTAkVVMUMwQQYDVQQHEzpNYWRyaWQgKHNlZSBjdXJyZW50IGFkZHJlc3MgYXQgd3d3LmNh
bWVyZmlybWEuY29tL2FkZHJlc3MpMRIwEAYDVQQFEwlBODI3NDMyODcxGzAZBgNVBAoTEkFDIENh
bWVyZmlybWEgUy5BLjEpMCcGA1UEAxMgQ2hhbWJlcnMgb2YgQ29tbWVyY2UgUm9vdCAtIDIwMDiC
CQCj2kJ+pLGu2jAOBgNVHQ8BAf8EBAMCAQYwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUH
AgEWHGh0dHA6Ly9wb2xpY3kuY2FtZXJmaXJtYS5jb20wDQYJKoZIhvcNAQEFBQADggIBAJASryI1
wqM58C7e6bXpeHxIvj99RZJe6dqxGfwWPJ+0W2aeaufDuV2I6A+tzyMP3iU6XsxPpcG1Lawk0lgH
3qLPaYRgM+gQDROpI9CF5Y57pp49chNyM/WqfcZjHwj0/gF/JM8rLFQJ3uIrbZLGOU8W6jx+ekbU
RWpGqOt1glanq6B8aBMz9p0w8G8nOSQjKpD9kCk18pPfNKXG9/jvjA9iSnyu0/VU+I22mlaHFoI6
M6taIgj3grrqLuBHmrS1RaMFO9ncLkVAO+rcf+g769HsJtg1pDDFOqxXnrN2pSB7+R5KBWIBpih1
YJeSDW4+TTdDDZIVnBgizVGZoCkaPF+KMjNbMMeJL0eYD6MDxvbxrN8y8NmBGuScvfaAFPDRLLmF
9dijscilIeUcE5fuDr3fKanvNFNb0+RqE4QGtjICxFKuItLcsiFCGtpA8CnJ7AoMXOLQusxI0zcK
zBIKinmwPQN/aUv0NCB9szTqjktk9T79syNnFQ0EuPAtwQlRPLJsFfClI9eDdOTlLsn+mCdCxqvG
nrDQWzilm1DefhiYtUU79nm06PcaewaD+9CL2rvHvRirCG88gGtAPxkZumWK5r7VXNM21+9AUiRg
OGcEMeyP84LG3rlV8zsxkVrctQgVrXYlCg17LofiDKYGvCYQbTed7N14jHyAxfDZd0jQ
-----END CERTIFICATE-----

Global Chambersign Root - 2008
==============================
-----BEGIN CERTIFICATE-----
MIIHSTCCBTGgAwIBAgIJAMnN0+nVfSPOMA0GCSqGSIb3DQEBBQUAMIGsMQswCQYDVQQGEwJFVTFD
MEEGA1UEBxM6TWFkcmlkIChzZWUgY3VycmVudCBhZGRyZXNzIGF0IHd3dy5jYW1lcmZpcm1hLmNv
bS9hZGRyZXNzKTESMBAGA1UEBRMJQTgyNzQzMjg3MRswGQYDVQQKExJBQyBDYW1lcmZpcm1hIFMu
QS4xJzAlBgNVBAMTHkdsb2JhbCBDaGFtYmVyc2lnbiBSb290IC0gMjAwODAeFw0wODA4MDExMjMx
NDBaFw0zODA3MzExMjMxNDBaMIGsMQswCQYDVQQGEwJFVTFDMEEGA1UEBxM6TWFkcmlkIChzZWUg
Y3VycmVudCBhZGRyZXNzIGF0IHd3dy5jYW1lcmZpcm1hLmNvbS9hZGRyZXNzKTESMBAGA1UEBRMJ
QTgyNzQzMjg3MRswGQYDVQQKExJBQyBDYW1lcmZpcm1hIFMuQS4xJzAlBgNVBAMTHkdsb2JhbCBD
aGFtYmVyc2lnbiBSb290IC0gMjAwODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMDf
VtPkOpt2RbQT2//BthmLN0EYlVJH6xedKYiONWwGMi5HYvNJBL99RDaxccy9Wglz1dmFRP+RVyXf
XjaOcNFccUMd2drvXNL7G706tcuto8xEpw2uIRU/uXpbknXYpBI4iRmKt4DS4jJvVpyR1ogQC7N0
ZJJ0YPP2zxhPYLIj0Mc7zmFLmY/CDNBAspjcDahOo7kKrmCgrUVSY7pmvWjg+b4aqIG7HkF4ddPB
/gBVsIdU6CeQNR1MM62X/JcumIS/LMmjv9GYERTtY/jKmIhYF5ntRQOXfjyGHoiMvvKRhI9lNNgA
TH23MRdaKXoKGCQwoze1eqkBfSbW+Q6OWfH9GzO1KTsXO0G2Id3UwD2ln58fQ1DJu7xsepeY7s2M
H/ucUa6LcL0nn3HAa6x9kGbo1106DbDVwo3VyJ2dwW3Q0L9R5OP4wzg2rtandeavhENdk5IMagfe
Ox2YItaswTXbo6Al/3K1dh3ebeksZixShNBFks4c5eUzHdwHU1SjqoI7mjcv3N2gZOnm3b2u/GSF
HTynyQbehP9r6GsaPMWis0L7iwk+XwhSx2LE1AVxv8Rk5Pihg+g+EpuoHtQ2TS9x9o0o9oOpE9Jh
wZG7SMA0j0GMS0zbaRL/UJScIINZc+18ofLx/d33SdNDWKBWY8o9PeU1VlnpDsogzCtLkykPAgMB
AAGjggFqMIIBZjASBgNVHRMBAf8ECDAGAQH/AgEMMB0GA1UdDgQWBBS5CcqcHtvTbDprru1U8VuT
BjUuXjCB4QYDVR0jBIHZMIHWgBS5CcqcHtvTbDprru1U8VuTBjUuXqGBsqSBrzCBrDELMAkGA1UE
BhMCRVUxQzBBBgNVBAcTOk1hZHJpZCAoc2VlIGN1cnJlbnQgYWRkcmVzcyBhdCB3d3cuY2FtZXJm
aXJtYS5jb20vYWRkcmVzcykxEjAQBgNVBAUTCUE4Mjc0MzI4NzEbMBkGA1UEChMSQUMgQ2FtZXJm
aXJtYSBTLkEuMScwJQYDVQQDEx5HbG9iYWwgQ2hhbWJlcnNpZ24gUm9vdCAtIDIwMDiCCQDJzdPp
1X0jzjAOBgNVHQ8BAf8EBAMCAQYwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0
dHA6Ly9wb2xpY3kuY2FtZXJmaXJtYS5jb20wDQYJKoZIhvcNAQEFBQADggIBAICIf3DekijZBZRG
/5BXqfEv3xoNa/p8DhxJJHkn2EaqbylZUohwEurdPfWbU1Rv4WCiqAm57OtZfMY18dwY6fFn5a+6
ReAJ3spED8IXDneRRXozX1+WLGiLwUePmJs9wOzL9dWCkoQ10b42OFZyMVtHLaoXpGNR6woBrX/s
dZ7LoR/xfxKxueRkf2fWIyr0uDldmOghp+G9PUIadJpwr2hsUF1Jz//7Dl3mLEfXgTpZALVza2Mg
9jFFCDkO9HB+QHBaP9BrQql0PSgvAm11cpUJjUhjxsYjV5KTXjXBjfkK9yydYhz2rXzdpjEetrHH
foUm+qRqtdpjMNHvkzeyZi99Bffnt0uYlDXA2TopwZ2yUDMdSqlapskD7+3056huirRXhOukP9Du
qqqHW2Pok+JrqNS4cnhrG+055F3Lm6qH1U9OAP7Zap88MQ8oAgF9mOinsKJknnn4SPIVqczmyETr
P3iZ8ntxPjzxmKfFGBI/5rsoM0LpRQp8bfKGeS/Fghl9CYl8slR2iK7ewfPM4W7bMdaTrpmg7yVq
c5iJWzouE4gev8CSlDQb4ye3ix5vQv/n6TebUB0tovkC7stYWDpxvGjjqsGvHCgfotwjZT+B6q6Z
09gwzxMNTxXJhLynSC34MCN32EZLeW32jO06f2ARePTpm67VVMB0gNELQp/B
-----END CERTIFICATE-----

Go Daddy Root Certificate Authority - G2
========================================
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMxEDAOBgNVBAgT
B0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMu
MTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5
MDkwMTAwMDAwMFoXDTM3MTIzMTIzNTk1OVowgYMxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6
b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjExMC8G
A1UEAxMoR28gRGFkZHkgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAL9xYgjx+lk09xvJGKP3gElY6SKDE6bFIEMBO4Tx5oVJnyfq
9oQbTqC023CYxzIBsQU+B07u9PpPL1kwIuerGVZr4oAH/PMWdYA5UXvl+TW2dE6pjYIT5LY/qQOD
+qK+ihVqf94Lw7YZFAXK6sOoBJQ7RnwyDfMAZiLIjWltNowRGLfTshxgtDj6AozO091GB94KPutd
fMh8+7ArU6SSYmlRJQVhGkSBjCypQ5Yj36w6gZoOKcUcqeldHraenjAKOc7xiID7S13MMuyFYkMl
NAJWJwGRtDtwKj9useiciAF9n9T521NtYJ2/LOdYq7hfRvzOxBsDPAnrSTFcaUaz4EcCAwEAAaNC
MEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDqahQcQZyi27/a9
BUFuIMGU2g/eMA0GCSqGSIb3DQEBCwUAA4IBAQCZ21151fmXWWcDYfF+OwYxdS2hII5PZYe096ac
vNjpL9DbWu7PdIxztDhC2gV7+AJ1uP2lsdeu9tfeE8tTEH6KRtGX+rcuKxGrkLAngPnon1rpN5+r
5N9ss4UXnT3ZJE95kTXWXwTrgIOrmgIttRD02JDHBHNA7XIloKmf7J6raBKZV8aPEjoJpL1E/QYV
N8Gb5DKj7Tjo2GTzLH4U/ALqn83/B2gX2yKQOC16jdFU8WnjXzPKej17CuPKf1855eJ1usV2GDPO
LPAvTK33sefOT6jEm0pUBsV/fdUID+Ic/n4XuKxe9tQWskMJDE32p2u0mYRlynqI4uJEvlz36hz1
-----END CERTIFICATE-----

Starfield Root Certificate Authority - G2
=========================================
-----BEGIN CERTIFICATE-----
MIID3TCCAsWgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCVVMxEDAOBgNVBAgT
B0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9s
b2dpZXMsIEluYy4xMjAwBgNVBAMTKVN0YXJmaWVsZCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0
eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIzNTk1OVowgY8xCzAJBgNVBAYTAlVTMRAw
DgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFyZmllbGQg
VGVjaG5vbG9naWVzLCBJbmMuMTIwMAYDVQQDEylTdGFyZmllbGQgUm9vdCBDZXJ0aWZpY2F0ZSBB
dXRob3JpdHkgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL3twQP89o/8ArFv
W59I2Z154qK3A2FWGMNHttfKPTUuiUP3oWmb3ooa/RMgnLRJdzIpVv257IzdIvpy3Cdhl+72WoTs
bhm5iSzchFvVdPtrX8WJpRBSiUZV9Lh1HOZ/5FSuS/hVclcCGfgXcVnrHigHdMWdSL5stPSksPNk
N3mSwOxGXn/hbVNMYq/NHwtjuzqd+/x5AJhhdM8mgkBj87JyahkNmcrUDnXMN/uLicFZ8WJ/X7Nf
ZTD4p7dNdloedl40wOiWVpmKs/B/pM293DIxfJHP4F8R+GuqSVzRmZTRouNjWwl2tVZi4Ut0HZbU
JtQIBFnQmA4O5t78w+wfkPECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFHwMMh+n2TB/xH1oo2Kooc6rB1snMA0GCSqGSIb3DQEBCwUAA4IBAQARWfol
TwNvlJk7mh+ChTnUdgWUXuEok21iXQnCoKjUsHU48TRqneSfioYmUeYs0cYtbpUgSpIB7LiKZ3sx
4mcujJUDJi5DnUox9g61DLu34jd/IroAow57UvtruzvE03lRTs2Q9GcHGcg8RnoNAX3FWOdt5oUw
F5okxBDgBPfg8n/Uqgr/Qh037ZTlZFkSIHc40zI+OIF1lnP6aI+xy84fxez6nH7PfrHxBy22/L/K
pL/QlwVKvOoYKAKQvVR4CSFx09F9HdkWsKlhPdAKACL8x3vLCWRFCztAgfd9fDL1mMpYjn0q7pBZ
c2T5NnReJaH1ZgUufzkVqSr7UIuOhWn0
-----END CERTIFICATE-----

Starfield Services Root Certificate Authority - G2
==================================================
-----BEGIN CERTIFICATE-----
MIID7zCCAtegAwIBAgIBADANBgkqhkiG9w0BAQsFADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgT
B0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9s
b2dpZXMsIEluYy4xOzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRl
IEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIzNTk1OVowgZgxCzAJBgNV
BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxT
dGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTswOQYDVQQDEzJTdGFyZmllbGQgU2VydmljZXMg
Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBANUMOsQq+U7i9b4Zl1+OiFOxHz/Lz58gE20pOsgPfTz3a3Y4Y9k2YKibXlwAgLIvWX/2
h/klQ4bnaRtSmpDhcePYLQ1Ob/bISdm28xpWriu2dBTrz/sm4xq6HZYuajtYlIlHVv8loJNwU4Pa
hHQUw2eeBGg6345AWh1KTs9DkTvnVtYAcMtS7nt9rjrnvDH5RfbCYM8TWQIrgMw0R9+53pBlbQLP
LJGmpufehRhJfGZOozptqbXuNC66DQO4M99H67FrjSXZm86B0UVGMpZwh94CDklDhbZsc7tk6mFB
rMnUVN+HL8cisibMn1lUaJ/8viovxFUcdUBgF4UCVTmLfwUCAwEAAaNCMEAwDwYDVR0TAQH/BAUw
AwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJxfAN+qAdcwKziIorhtSpzyEZGDMA0GCSqG
SIb3DQEBCwUAA4IBAQBLNqaEd2ndOxmfZyMIbw5hyf2E3F/YNoHN2BtBLZ9g3ccaaNnRbobhiCPP
E95Dz+I0swSdHynVv/heyNXBve6SbzJ08pGCL72CQnqtKrcgfU28elUSwhXqvfdqlS5sdJ/PHLTy
xQGjhdByPq1zqwubdQxtRbeOlKyWN7Wg0I8VRw7j6IPdj/3vQQF3zCepYoUz8jcI73HPdwbeyBkd
iEDPfUYd/x7H4c7/I9vG+o1VTqkC50cRRj70/b17KSa7qWFiNyi2LSr2EIZkyXCn0q23KXB56jza
YyWf/Wi3MOxw+3WKt21gZ7IeyLnp2KhvAotnDU0mV3HaIPzBSlCNsSi6
-----END CERTIFICATE-----

AffirmTrust Commercial
======================
-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIId3cGJyapsXwwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCVVMxFDAS
BgNVBAoMC0FmZmlybVRydXN0MR8wHQYDVQQDDBZBZmZpcm1UcnVzdCBDb21tZXJjaWFsMB4XDTEw
MDEyOTE0MDYwNloXDTMwMTIzMTE0MDYwNlowRDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC0FmZmly
bVRydXN0MR8wHQYDVQQDDBZBZmZpcm1UcnVzdCBDb21tZXJjaWFsMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA9htPZwcroRX1BiLLHwGy43NFBkRJLLtJJRTWzsO3qyxPxkEylFf6Eqdb
DuKPHx6GGaeqtS25Xw2Kwq+FNXkyLbscYjfysVtKPcrNcV/pQr6U6Mje+SJIZMblq8Yrba0F8PrV
C8+a5fBQpIs7R6UjW3p6+DM/uO+Zl+MgwdYoic+U+7lF7eNAFxHUdPALMeIrJmqbTFeurCA+ukV6
BfO9m2kVrn1OIGPENXY6BwLJN/3HR+7o8XYdcxXyl6S1yHp52UKqK39c/s4mT6NmgTWvRLpUHhww
MmWd5jyTXlBOeuM61G7MGvv50jeuJCqrVwMiKA1JdX+3KNp1v47j3A55MQIDAQABo0IwQDAdBgNV
HQ4EFgQUnZPGU4teyq8/nx4P5ZmVvCT2lI8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AQYwDQYJKoZIhvcNAQELBQADggEBAFis9AQOzcAN/wr91LoWXym9e2iZWEnStB03TX8nfUYGXUPG
hi4+c7ImfU+TqbbEKpqrIZcUsd6M06uJFdhrJNTxFq7YpFzUf1GO7RgBsZNjvbz4YYCanrHOQnDi
qX0GJX0nof5v7LMeJNrjS1UaADs1tDvZ110w/YETifLCBivtZ8SOyUOyXGsViQK8YvxO8rUzqrJv
0wqiUOP2O+guRMLbZjipM1ZI8W0bM40NjD9gN53Tym1+NH4Nn3J2ixufcv1SNUFFApYvHLKac0kh
sUlHRUe072o0EclNmsxZt9YCnlpOZbWUrhvfKbAW8b8Angc6F2S1BLUjIZkKlTuXfO8=
-----END CERTIFICATE-----

AffirmTrust Networking
======================
-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIIfE8EORzUmS0wDQYJKoZIhvcNAQEFBQAwRDELMAkGA1UEBhMCVVMxFDAS
BgNVBAoMC0FmZmlybVRydXN0MR8wHQYDVQQDDBZBZmZpcm1UcnVzdCBOZXR3b3JraW5nMB4XDTEw
MDEyOTE0MDgyNFoXDTMwMTIzMTE0MDgyNFowRDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC0FmZmly
bVRydXN0MR8wHQYDVQQDDBZBZmZpcm1UcnVzdCBOZXR3b3JraW5nMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAtITMMxcua5Rsa2FSoOujz3mUTOWUgJnLVWREZY9nZOIG41w3SfYvm4SE
Hi3yYJ0wTsyEheIszx6e/jarM3c1RNg1lho9Nuh6DtjVR6FqaYvZ/Ls6rnla1fTWcbuakCNrmreI
dIcMHl+5ni36q1Mr3Lt2PpNMCAiMHqIjHNRqrSK6mQEubWXLviRmVSRLQESxG9fhwoXA3hA/Pe24
/PHxI1Pcv2WXb9n5QHGNfb2V1M6+oF4nI979ptAmDgAp6zxG8D1gvz9Q0twmQVGeFDdCBKNwV6gb
h+0t+nvujArjqWaJGctB+d1ENmHP4ndGyH329JKBNv3bNPFyfvMMFr20FQIDAQABo0IwQDAdBgNV
HQ4EFgQUBx/S55zawm6iQLSwelAQUHTEyL0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AQYwDQYJKoZIhvcNAQEFBQADggEBAIlXshZ6qML91tmbmzTCnLQyFE2npN/svqe++EPbkTfOtDIu
UFUaNU52Q3Eg75N3ThVwLofDwR1t3Mu1J9QsVtFSUzpE0nPIxBsFZVpikpzuQY0x2+c06lkh1QF6
12S4ZDnNye2v7UsDSKegmQGA3GWjNq5lWUhPgkvIZfFXHeVZLgo/bNjR9eUJtGxUAArgFU2HdW23
WJZa3W3SAKD0m0i+wzekujbgfIeFlxoVot4uolu9rxj5kFDNcFn4J2dHy8egBzp90SxdbBk6ZrV9
/ZFvgrG+CJPbFEfxojfHRZ48x3evZKiT3/Zpg4Jg8klCNO1aAFSFHBY2kgxc+qatv9s=
-----END CERTIFICATE-----

AffirmTrust Premium
===================
-----BEGIN CERTIFICATE-----
MIIFRjCCAy6gAwIBAgIIbYwURrGmCu4wDQYJKoZIhvcNAQEMBQAwQTELMAkGA1UEBhMCVVMxFDAS
BgNVBAoMC0FmZmlybVRydXN0MRwwGgYDVQQDDBNBZmZpcm1UcnVzdCBQcmVtaXVtMB4XDTEwMDEy
OTE0MTAzNloXDTQwMTIzMTE0MTAzNlowQTELMAkGA1UEBhMCVVMxFDASBgNVBAoMC0FmZmlybVRy
dXN0MRwwGgYDVQQDDBNBZmZpcm1UcnVzdCBQcmVtaXVtMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAxBLfqV/+Qd3d9Z+K4/as4Tx4mrzY8H96oDMq3I0gW64tb+eT2TZwamjPjlGjhVtn
BKAQJG9dKILBl1fYSCkTtuG+kU3fhQxTGJoeJKJPj/CihQvL9Cl/0qRY7iZNyaqoe5rZ+jjeRFcV
5fiMyNlI4g0WJx0eyIOFJbe6qlVBzAMiSy2RjYvmia9mx+n/K+k8rNrSs8PhaJyJ+HoAVt70VZVs
+7pk3WKL3wt3MutizCaam7uqYoNMtAZ6MMgpv+0GTZe5HMQxK9VfvFMSF5yZVylmd2EhMQcuJUmd
GPLu8ytxjLW6OQdJd/zvLpKQBY0tL3d770O/Nbua2Plzpyzy0FfuKE4mX4+QaAkvuPjcBukumj5R
p9EixAqnOEhss/n/fauGV+O61oV4d7pD6kh/9ti+I20ev9E2bFhc8e6kGVQa9QPSdubhjL08s9NI
S+LI+H+SqHZGnEJlPqQewQcDWkYtuJfzt9WyVSHvutxMAJf7FJUnM7/oQ0dG0giZFmA7mn7S5u04
6uwBHjxIVkkJx0w3AJ6IDsBz4W9m6XJHMD4Q5QsDyZpCAGzFlH5hxIrff4IaC1nEWTJ3s7xgaVY5
/bQGeyzWZDbZvUjthB9+pSKPKrhC9IK31FOQeE4tGv2Bb0TXOwF0lkLgAOIua+rF7nKsu7/+6qqo
+Nz2snmKtmcCAwEAAaNCMEAwHQYDVR0OBBYEFJ3AZ6YMItkm9UWrpmVSESfYRaxjMA8GA1UdEwEB
/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBDAUAA4ICAQCzV00QYk465KzquByv
MiPIs0laUZx2KI15qldGF9X1Uva3ROgIRL8YhNILgM3FEv0AVQVhh0HctSSePMTYyPtwni94loMg
Nt58D2kTiKV1NpgIpsbfrM7jWNa3Pt668+s0QNiigfV4Py/VpfzZotReBA4Xrf5B8OWycvpEgjNC
6C1Y91aMYj+6QrCcDFx+LmUmXFNPALJ4fqENmS2NuB2OosSw/WDQMKSOyARiqcTtNd56l+0OOF6S
L5Nwpamcb6d9Ex1+xghIsV5n61EIJenmJWtSKZGc0jlzCFfemQa0W50QBuHCAKi4HEoCChTQwUHK
+4w1IX2COPKpVJEZNZOUbWo6xbLQu4mGk+ibyQ86p3q4ofB4Rvr8Ny/lioTz3/4E2aFooC8k4gmV
BtWVyuEklut89pMFu+1z6S3RdTnX5yTb2E5fQ4+e0BQ5v1VwSJlXMbSc7kqYA5YwH2AG7hsj/oFg
IxpHYoWlzBk0gG+zrBrjn/B7SK3VAdlntqlyk+otZrWyuOQ9PLLvTIzq6we/qzWaVYa8GKa1qF60
g2xraUDTn9zxw2lrueFtCfTxqlB2Cnp9ehehVZZCmTEJ3WARjQUwfuaORtGdFNrHF+QFlozEJLUb
zxQHskD4o55BhrwE0GuWyCqANP2/7waj3VjFhT0+j/6eKeC2uAloGRwYQw==
-----END CERTIFICATE-----

AffirmTrust Premium ECC
=======================
-----BEGIN CERTIFICATE-----
MIIB/jCCAYWgAwIBAgIIdJclisc/elQwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxFDASBgNV
BAoMC0FmZmlybVRydXN0MSAwHgYDVQQDDBdBZmZpcm1UcnVzdCBQcmVtaXVtIEVDQzAeFw0xMDAx
MjkxNDIwMjRaFw00MDEyMzExNDIwMjRaMEUxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtBZmZpcm1U
cnVzdDEgMB4GA1UEAwwXQWZmaXJtVHJ1c3QgUHJlbWl1bSBFQ0MwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAQNMF4bFZ0D0KF5Nbc6PJJ6yhUczWLznCZcBz3lVPqj1swS6vQUX+iOGasvLkjmrBhDeKzQ
N8O9ss0s5kfiGuZjuD0uL3jET9v0D6RoTFVya5UdThhClXjMNzyR4ptlKymjQjBAMB0GA1UdDgQW
BBSaryl6wBE1NSZRMADDav5A1a7WPDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAK
BggqhkjOPQQDAwNnADBkAjAXCfOHiFBar8jAQr9HX/VsaobgxCd05DhT1wV/GzTjxi+zygk8N53X
57hG8f2h4nECMEJZh0PUUd+60wkyWs6Iflc9nF9Ca/UHLbXwgpP5WW+uZPpY5Yse42O+tYHNbwKM
eQ==
-----END CERTIFICATE-----

Certum Trusted Network CA
=========================
-----BEGIN CERTIFICATE-----
MIIDuzCCAqOgAwIBAgIDBETAMA0GCSqGSIb3DQEBBQUAMH4xCzAJBgNVBAYTAlBMMSIwIAYDVQQK
ExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVzdGVkIE5ldHdvcmsgQ0EwHhcNMDgxMDIy
MTIwNzM3WhcNMjkxMjMxMTIwNzM3WjB+MQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBU
ZWNobm9sb2dpZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
MSIwIAYDVQQDExlDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA4/t9o3K6wvDJFIf1awFO4W5AB7ptJ11/91sts1rHUV+rpDKmYYe2bg+G0jAC
l/jXaVehGDldamR5xgFZrDwxSjh80gTSSyjoIF87B6LMTXPb865Px1bVWqeWifrzq2jUI4ZZJ88J
J7ysbnKDHDBy3+Ci6dLhdHUZvSqeexVUBBvXQzmtVSjF4hq79MDkrjhJM8x2hZ85RdKknvISjFH4
fOQtf/WsX+sWn7Et0brMkUJ3TCXJkDhv2/DM+44el1k+1WBO5gUo7Ul5E0u6SNsv+XLTOcr+H9g0
cvW0QM8xAcPs3hEtF10fuFDRXhmnad4HMyjKUJX5p1TLVIZQRan5SQIDAQABo0IwQDAPBgNVHRMB
Af8EBTADAQH/MB0GA1UdDgQWBBQIds3LB/8k9sXN7buQvOKEN0Z19zAOBgNVHQ8BAf8EBAMCAQYw
DQYJKoZIhvcNAQEFBQADggEBAKaorSLOAT2mo/9i0Eidi15ysHhE49wcrwn9I0j6vSrEuVUEtRCj
jSfeC4Jj0O7eDDd5QVsisrCaQVymcODU0HfLI9MA4GxWL+FpDQ3Zqr8hgVDZBqWo/5U30Kr+4rP1
mS1FhIrlQgnXdAIv94nYmem8J9RHjboNRhx3zxSkHLmkMcScKHQDNP8zGSal6Q10tz6XxnboJ5aj
Zt3hrvJBW8qYVoNzcOSGGtIxQbovvi0TWnZvTuhOgQ4/WwMioBK+ZlgRSssDxLQqKi2WF+A5VLxI
03YnnZotBqbJ7DnSq9ufmgsnAjUpsUCV5/nonFWIGUbWtzT1fs45mtk48VH3Tyw=
-----END CERTIFICATE-----

TWCA Root Certification Authority
=================================
-----BEGIN CERTIFICATE-----
MIIDezCCAmOgAwIBAgIBATANBgkqhkiG9w0BAQUFADBfMQswCQYDVQQGEwJUVzESMBAGA1UECgwJ
VEFJV0FOLUNBMRAwDgYDVQQLDAdSb290IENBMSowKAYDVQQDDCFUV0NBIFJvb3QgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwHhcNMDgwODI4MDcyNDMzWhcNMzAxMjMxMTU1OTU5WjBfMQswCQYDVQQG
EwJUVzESMBAGA1UECgwJVEFJV0FOLUNBMRAwDgYDVQQLDAdSb290IENBMSowKAYDVQQDDCFUV0NB
IFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCwfnK4pAOU5qfeCTiRShFAh6d8WWQUe7UREN3+v9XAu1bihSX0NXIP+FPQQeFEAcK0HMMx
QhZHhTMidrIKbw/lJVBPhYa+v5guEGcevhEFhgWQxFnQfHgQsIBct+HHK3XLfJ+utdGdIzdjp9xC
oi2SBBtQwXu4PhvJVgSLL1KbralW6cH/ralYhzC2gfeXRfwZVzsrb+RH9JlF/h3x+JejiB03HFyP
4HYlmlD4oFT/RJB2I9IyxsOrBr/8+7/zrX2SYgJbKdM1o5OaQ2RgXbL6Mv87BK9NQGr5x+PvI/1r
y+UPizgN7gr8/g+YnzAx3WxSZfmLgb4i4RxYA7qRG4kHAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIB
BjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRqOFsmjd6LWvJPelSDGRjjCDWmujANBgkqhkiG
9w0BAQUFAAOCAQEAPNV3PdrfibqHDAhUaiBQkr6wQT25JmSDCi/oQMCXKCeCMErJk/9q56YAf4lC
mtYR5VPOL8zy2gXE/uJQxDqGfczafhAJO5I1KlOy/usrBdlsXebQ79NqZp4VKIV66IIArB6nCWlW
QtNoURi+VJq/REG6Sb4gumlc7rh3zc5sH62Dlhh9DrUUOYTxKOkto557HnpyWoOzeW/vtPzQCqVY
T0bf+215WfKEIlKuD8z7fDvnaspHYcN6+NOSBB+4IIThNlQWx0DeO4pz3N/GCUzf7Nr/1FNCocny
Yh0igzyXxfkZYiesZSLX0zzG5Y6yU8xJzrww/nsOM5D77dIUkR8Hrw==
-----END CERTIFICATE-----

Security Communication RootCA2
==============================
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIBADANBgkqhkiG9w0BAQsFADBdMQswCQYDVQQGEwJKUDElMCMGA1UEChMc
U0VDT00gVHJ1c3QgU3lzdGVtcyBDTy4sTFRELjEnMCUGA1UECxMeU2VjdXJpdHkgQ29tbXVuaWNh
dGlvbiBSb290Q0EyMB4XDTA5MDUyOTA1MDAzOVoXDTI5MDUyOTA1MDAzOVowXTELMAkGA1UEBhMC
SlAxJTAjBgNVBAoTHFNFQ09NIFRydXN0IFN5c3RlbXMgQ08uLExURC4xJzAlBgNVBAsTHlNlY3Vy
aXR5IENvbW11bmljYXRpb24gUm9vdENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANAVOVKxUrO6xVmCxF1SrjpDZYBLx/KWvNs2l9amZIyoXvDjChz335c9S672XewhtUGrzbl+dp++
+T42NKA7wfYxEUV0kz1XgMX5iZnK5atq1LXaQZAQwdbWQonCv/Q4EpVMVAX3NuRFg3sUZdbcDE3R
3n4MqzvEFb46VqZab3ZpUql6ucjrappdUtAtCms1FgkQhNBqyjoGADdH5H5XTz+L62e4iKrFvlNV
spHEfbmwhRkGeC7bYRr6hfVKkaHnFtWOojnflLhwHyg/i/xAXmODPIMqGplrz95Zajv8bxbXH/1K
EOtOghY6rCcMU/Gt1SSwawNQwS08Ft1ENCcadfsCAwEAAaNCMEAwHQYDVR0OBBYEFAqFqXdlBZh8
QIH4D5csOPEK7DzPMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB
CwUAA4IBAQBMOqNErLlFsceTfsgLCkLfZOoc7llsCLqJX2rKSpWeeo8HxdpFcoJxDjrSzG+ntKEj
u/Ykn8sX/oymzsLS28yN/HH8AynBbF0zX2S2ZTuJbxh2ePXcokgfGT+Ok+vx+hfuzU7jBBJV1uXk
3fs+BXziHV7Gp7yXT2g69ekuCkO2r1dcYmh8t/2jioSgrGK+KwmHNPBqAbubKVY8/gA3zyNs8U6q
tnRGEmyR7jTV7JqR50S+kDFy1UkC9gLl9B/rfNmWVan/7Ir5mUf/NVoCqgTLiluHcSmRvaS0eg29
mvVXIwAHIRc/SjnRBUkLp7Y3gaVdjKozXoEofKd9J+sAro03
-----END CERTIFICATE-----

EC-ACC
======
-----BEGIN CERTIFICATE-----
MIIFVjCCBD6gAwIBAgIQ7is969Qh3hSoYqwE893EATANBgkqhkiG9w0BAQUFADCB8zELMAkGA1UE
BhMCRVMxOzA5BgNVBAoTMkFnZW5jaWEgQ2F0YWxhbmEgZGUgQ2VydGlmaWNhY2lvIChOSUYgUS0w
ODAxMTc2LUkpMSgwJgYDVQQLEx9TZXJ2ZWlzIFB1YmxpY3MgZGUgQ2VydGlmaWNhY2lvMTUwMwYD
VQQLEyxWZWdldSBodHRwczovL3d3dy5jYXRjZXJ0Lm5ldC92ZXJhcnJlbCAoYykwMzE1MDMGA1UE
CxMsSmVyYXJxdWlhIEVudGl0YXRzIGRlIENlcnRpZmljYWNpbyBDYXRhbGFuZXMxDzANBgNVBAMT
BkVDLUFDQzAeFw0wMzAxMDcyMzAwMDBaFw0zMTAxMDcyMjU5NTlaMIHzMQswCQYDVQQGEwJFUzE7
MDkGA1UEChMyQWdlbmNpYSBDYXRhbGFuYSBkZSBDZXJ0aWZpY2FjaW8gKE5JRiBRLTA4MDExNzYt
SSkxKDAmBgNVBAsTH1NlcnZlaXMgUHVibGljcyBkZSBDZXJ0aWZpY2FjaW8xNTAzBgNVBAsTLFZl
Z2V1IGh0dHBzOi8vd3d3LmNhdGNlcnQubmV0L3ZlcmFycmVsIChjKTAzMTUwMwYDVQQLEyxKZXJh
cnF1aWEgRW50aXRhdHMgZGUgQ2VydGlmaWNhY2lvIENhdGFsYW5lczEPMA0GA1UEAxMGRUMtQUND
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsyLHT+KXQpWIR4NA9h0X84NzJB5R85iK
w5K4/0CQBXCHYMkAqbWUZRkiFRfCQ2xmRJoNBD45b6VLeqpjt4pEndljkYRm4CgPukLjbo73FCeT
ae6RDqNfDrHrZqJyTxIThmV6PttPB/SnCWDaOkKZx7J/sxaVHMf5NLWUhdWZXqBIoH7nF2W4onW4
HvPlQn2v7fOKSGRdghST2MDk/7NQcvJ29rNdQlB50JQ+awwAvthrDk4q7D7SzIKiGGUzE3eeml0a
E9jD2z3Il3rucO2n5nzbcc8tlGLfbdb1OL4/pYUKGbio2Al1QnDE6u/LDsg0qBIimAy4E5S2S+zw
0JDnJwIDAQABo4HjMIHgMB0GA1UdEQQWMBSBEmVjX2FjY0BjYXRjZXJ0Lm5ldDAPBgNVHRMBAf8E
BTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUoMOLRKo3pUW/l4Ba0fF4opvpXY0wfwYD
VR0gBHgwdjB0BgsrBgEEAfV4AQMBCjBlMCwGCCsGAQUFBwIBFiBodHRwczovL3d3dy5jYXRjZXJ0
Lm5ldC92ZXJhcnJlbDA1BggrBgEFBQcCAjApGidWZWdldSBodHRwczovL3d3dy5jYXRjZXJ0Lm5l
dC92ZXJhcnJlbCAwDQYJKoZIhvcNAQEFBQADggEBAKBIW4IB9k1IuDlVNZyAelOZ1Vr/sXE7zDkJ
lF7W2u++AVtd0x7Y/X1PzaBB4DSTv8vihpw3kpBWHNzrKQXlxJ7HNd+KDM3FIUPpqojlNcAZQmNa
Al6kSBg6hW/cnbw/nZzBh7h6YQjpdwt/cKt63dmXLGQehb+8dJahw3oS7AwaboMMPOhyRp/7SNVe
l+axofjk70YllJyJ22k4vuxcDlbHZVHlUIiIv0LVKz3l+bqeLrPK9HOSAgu+TGbrIP65y7WZf+a2
E/rKS03Z7lNGBjvGTq2TWoF+bCpLagVFjPIhpDGQh2xlnJ2lYJU6Un/10asIbvPuW/mIPX64b24D
5EI=
-----END CERTIFICATE-----

Hellenic Academic and Research Institutions RootCA 2011
=======================================================
-----BEGIN CERTIFICATE-----
MIIEMTCCAxmgAwIBAgIBADANBgkqhkiG9w0BAQUFADCBlTELMAkGA1UEBhMCR1IxRDBCBgNVBAoT
O0hlbGxlbmljIEFjYWRlbWljIGFuZCBSZXNlYXJjaCBJbnN0aXR1dGlvbnMgQ2VydC4gQXV0aG9y
aXR5MUAwPgYDVQQDEzdIZWxsZW5pYyBBY2FkZW1pYyBhbmQgUmVzZWFyY2ggSW5zdGl0dXRpb25z
IFJvb3RDQSAyMDExMB4XDTExMTIwNjEzNDk1MloXDTMxMTIwMTEzNDk1MlowgZUxCzAJBgNVBAYT
AkdSMUQwQgYDVQQKEztIZWxsZW5pYyBBY2FkZW1pYyBhbmQgUmVzZWFyY2ggSW5zdGl0dXRpb25z
IENlcnQuIEF1dGhvcml0eTFAMD4GA1UEAxM3SGVsbGVuaWMgQWNhZGVtaWMgYW5kIFJlc2VhcmNo
IEluc3RpdHV0aW9ucyBSb290Q0EgMjAxMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AKlTAOMupvaO+mDYLZU++CwqVE7NuYRhlFhPjz2L5EPzdYmNUeTDN9KKiE15HrcS3UN4SoqS5tdI
1Q+kOilENbgH9mgdVc04UfCMJDGFr4PJfel3r+0ae50X+bOdOFAPplp5kYCvN66m0zH7tSYJnTxa
71HFK9+WXesyHgLacEnsbgzImjeN9/E2YEsmLIKe0HjzDQ9jpFEw4fkrJxIH2Oq9GGKYsFk3fb7u
8yBRQlqD75O6aRXxYp2fmTmCobd0LovUxQt7L/DICto9eQqakxylKHJzkUOap9FNhYS5qXSPFEDH
3N6sQWRstBmbAmNtJGSPRLIl6s5ddAxjMlyNh+UCAwEAAaOBiTCBhjAPBgNVHRMBAf8EBTADAQH/
MAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQUppFC/RNhSiOeCKQp5dgTBCPuQSUwRwYDVR0eBEAwPqA8
MAWCAy5ncjAFggMuZXUwBoIELmVkdTAGggQub3JnMAWBAy5ncjAFgQMuZXUwBoEELmVkdTAGgQQu
b3JnMA0GCSqGSIb3DQEBBQUAA4IBAQAf73lB4XtuP7KMhjdCSk4cNx6NZrokgclPEg8hwAOXhiVt
XdMiKahsog2p6z0GW5k6x8zDmjR/qw7IThzh+uTczQ2+vyT+bOdrwg3IBp5OjWEopmr95fZi6hg8
TqBTnbI6nOulnJEWtk2C4AwFSKls9cz4y51JtPACpf1wA+2KIaWuE4ZJwzNzvoc7dIsXRSZMFpGD
/md9zU1jZ/rzAxKWeAaNsWftjj++n08C9bMJL/NMh98qy5V8AcysNnq/onN694/BtZqhFLKPM58N
7yLcZnuEvUUXBj08yrl3NI/K6s8/MT7jiOOASSXIl7WdmplNsDz4SgCbZN2fOUvRJ9e4
-----END CERTIFICATE-----

Actalis Authentication Root CA
==============================
-----BEGIN CERTIFICATE-----
MIIFuzCCA6OgAwIBAgIIVwoRl0LE48wwDQYJKoZIhvcNAQELBQAwazELMAkGA1UEBhMCSVQxDjAM
BgNVBAcMBU1pbGFuMSMwIQYDVQQKDBpBY3RhbGlzIFMucC5BLi8wMzM1ODUyMDk2NzEnMCUGA1UE
AwweQWN0YWxpcyBBdXRoZW50aWNhdGlvbiBSb290IENBMB4XDTExMDkyMjExMjIwMloXDTMwMDky
MjExMjIwMlowazELMAkGA1UEBhMCSVQxDjAMBgNVBAcMBU1pbGFuMSMwIQYDVQQKDBpBY3RhbGlz
IFMucC5BLi8wMzM1ODUyMDk2NzEnMCUGA1UEAwweQWN0YWxpcyBBdXRoZW50aWNhdGlvbiBSb290
IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAp8bEpSmkLO/lGMWwUKNvUTufClrJ
wkg4CsIcoBh/kbWHuUA/3R1oHwiD1S0eiKD4j1aPbZkCkpAW1V8IbInX4ay8IMKx4INRimlNAJZa
by/ARH6jDuSRzVju3PvHHkVH3Se5CAGfpiEd9UEtL0z9KK3giq0itFZljoZUj5NDKd45RnijMCO6
zfB9E1fAXdKDa0hMxKufgFpbOr3JpyI/gCczWw63igxdBzcIy2zSekciRDXFzMwujt0q7bd9Zg1f
YVEiVRvjRuPjPdA1YprbrxTIW6HMiRvhMCb8oJsfgadHHwTrozmSBp+Z07/T6k9QnBn+locePGX2
oxgkg4YQ51Q+qDp2JE+BIcXjDwL4k5RHILv+1A7TaLndxHqEguNTVHnd25zS8gebLra8Pu2Fbe8l
EfKXGkJh90qX6IuxEAf6ZYGyojnP9zz/GPvG8VqLWeICrHuS0E4UT1lF9gxeKF+w6D9Fz8+vm2/7
hNN3WpVvrJSEnu68wEqPSpP4RCHiMUVhUE4Q2OM1fEwZtN4Fv6MGn8i1zeQf1xcGDXqVdFUNaBr8
EBtiZJ1t4JWgw5QHVw0U5r0F+7if5t+L4sbnfpb2U8WANFAoWPASUHEXMLrmeGO89LKtmyuy/uE5
jF66CyCU3nuDuP/jVo23Eek7jPKxwV2dpAtMK9myGPW1n0sCAwEAAaNjMGEwHQYDVR0OBBYEFFLY
iDrIn3hm7YnzezhwlMkCAjbQMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUUtiIOsifeGbt
ifN7OHCUyQICNtAwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4ICAQALe3KHwGCmSUyI
WOYdiPcUZEim2FgKDk8TNd81HdTtBjHIgT5q1d07GjLukD0R0i70jsNjLiNmsGe+b7bAEzlgqqI0
JZN1Ut6nna0Oh4lScWoWPBkdg/iaKWW+9D+a2fDzWochcYBNy+A4mz+7+uAwTc+G02UQGRjRlwKx
K3JCaKygvU5a2hi/a5iB0P2avl4VSM0RFbnAKVy06Ij3Pjaut2L9HmLecHgQHEhb2rykOLpn7VU+
Xlff1ANATIGk0k9jpwlCCRT8AKnCgHNPLsBA2RF7SOp6AsDT6ygBJlh0wcBzIm2Tlf05fbsq4/aC
4yyXX04fkZT6/iyj2HYauE2yOE+b+h1IYHkm4vP9qdCa6HCPSXrW5b0KDtst842/6+OkfcvHlXHo
2qN8xcL4dJIEG4aspCJTQLas/kx2z/uUMsA1n3Y/buWQbqCmJqK4LL7RK4X9p2jIugErsWx0Hbhz
lefut8cl8ABMALJ+tguLHPPAUJ4lueAI3jZm/zel0btUZCzJJ7VLkn5l/9Mt4blOvH+kQSGQQXem
OR/qnuOf0GZvBeyqdn6/axag67XH/JJULysRJyU3eExRarDzzFhdFPFqSBX/wge2sY0PjlxQRrM9
vwGYT7JZVEc+NHt4bVaTLnPqZih4zR0Uv6CPLy64Lo7yFIrM6bV8+2ydDKXhlg==
-----END CERTIFICATE-----

Trustis FPS Root CA
===================
-----BEGIN CERTIFICATE-----
MIIDZzCCAk+gAwIBAgIQGx+ttiD5JNM2a/fH8YygWTANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQG
EwJHQjEYMBYGA1UEChMPVHJ1c3RpcyBMaW1pdGVkMRwwGgYDVQQLExNUcnVzdGlzIEZQUyBSb290
IENBMB4XDTAzMTIyMzEyMTQwNloXDTI0MDEyMTExMzY1NFowRTELMAkGA1UEBhMCR0IxGDAWBgNV
BAoTD1RydXN0aXMgTGltaXRlZDEcMBoGA1UECxMTVHJ1c3RpcyBGUFMgUm9vdCBDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVQe547NdDfxIzNjpvto8A2mfRC6qc+gIMPpqdZh8mQ
RUN+AOqGeSoDvT03mYlmt+WKVoaTnGhLaASMk5MCPjDSNzoiYYkchU59j9WvezX2fihHiTHcDnlk
H5nSW7r+f2C/revnPDgpai/lkQtV/+xvWNUtyd5MZnGPDNcE2gfmHhjjvSkCqPoc4Vu5g6hBSLwa
cY3nYuUtsuvffM/bq1rKMfFMIvMFE/eC+XN5DL7XSxzA0RU8k0Fk0ea+IxciAIleH2ulrG6nS4zt
o3Lmr2NNL4XSFDWaLk6M6jKYKIahkQlBOrTh4/L68MkKokHdqeMDx4gVOxzUGpTXn2RZEm0CAwEA
AaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS6+nEleYtXQSUhhgtx67JkDoshZzAd
BgNVHQ4EFgQUuvpxJXmLV0ElIYYLceuyZA6LIWcwDQYJKoZIhvcNAQEFBQADggEBAH5Y//01GX2c
GE+esCu8jowU/yyg2kdbw++BLa8F6nRIW/M+TgfHbcWzk88iNVy2P3UnXwmWzaD+vkAMXBJV+JOC
yinpXj9WV4s4NvdFGkwozZ5BuO1WTISkQMi4sKUraXAEasP41BIy+Q7DsdwyhEQsb8tGD+pmQQ9P
8Vilpg0ND2HepZ5dfWWhPBfnqFVO76DH7cZEf1T1o+CP8HxVIo8ptoGj4W1OLBuAZ+ytIJ8MYmHV
l/9D7S3B2l0pKoU/rGXuhg8FjZBf3+6f9L/uHfuY5H+QK4R4EA5sSVPvFVtlRkpdr7r7OnIdzfYl
iB6XzCGcKQENZetX2fNXlrtIzYE=
-----END CERTIFICATE-----

Buypass Class 2 Root CA
=======================
-----BEGIN CERTIFICATE-----
MIIFWTCCA0GgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJOTzEdMBsGA1UECgwU
QnV5cGFzcyBBUy05ODMxNjMzMjcxIDAeBgNVBAMMF0J1eXBhc3MgQ2xhc3MgMiBSb290IENBMB4X
DTEwMTAyNjA4MzgwM1oXDTQwMTAyNjA4MzgwM1owTjELMAkGA1UEBhMCTk8xHTAbBgNVBAoMFEJ1
eXBhc3MgQVMtOTgzMTYzMzI3MSAwHgYDVQQDDBdCdXlwYXNzIENsYXNzIDIgUm9vdCBDQTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANfHXvfBB9R3+0Mh9PT1aeTuMgHbo4Yf5FkNuud1
g1Lr6hxhFUi7HQfKjK6w3Jad6sNgkoaCKHOcVgb/S2TwDCo3SbXlzwx87vFKu3MwZfPVL4O2fuPn
9Z6rYPnT8Z2SdIrkHJasW4DptfQxh6NR/Md+oW+OU3fUl8FVM5I+GC911K2GScuVr1QGbNgGE41b
/+EmGVnAJLqBcXmQRFBoJJRfuLMR8SlBYaNByyM21cHxMlAQTn/0hpPshNOOvEu/XAFOBz3cFIqU
CqTqc/sLUegTBxj6DvEr0VQVfTzh97QZQmdiXnfgolXsttlpF9U6r0TtSsWe5HonfOV116rLJeff
awrbD02TTqigzXsu8lkBarcNuAeBfos4GzjmCleZPe4h6KP1DBbdi+w0jpwqHAAVF41og9JwnxgI
zRFo1clrUs3ERo/ctfPYV3Me6ZQ5BL/T3jjetFPsaRyifsSP5BtwrfKi+fv3FmRmaZ9JUaLiFRhn
Bkp/1Wy1TbMz4GHrXb7pmA8y1x1LPC5aAVKRCfLf6o3YBkBjqhHk/sM3nhRSP/TizPJhk9H9Z2vX
Uq6/aKtAQ6BXNVN48FP4YUIHZMbXb5tMOA1jrGKvNouicwoN9SG9dKpN6nIDSdvHXx1iY8f93ZHs
M+71bbRuMGjeyNYmsHVee7QHIJihdjK4TWxPAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFMmAd+BikoL1RpzzuvdMw964o605MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsF
AAOCAgEAU18h9bqwOlI5LJKwbADJ784g7wbylp7ppHR/ehb8t/W2+xUbP6umwHJdELFx7rxP462s
A20ucS6vxOOto70MEae0/0qyexAQH6dXQbLArvQsWdZHEIjzIVEpMMpghq9Gqx3tOluwlN5E40EI
osHsHdb9T7bWR9AUC8rmyrV7d35BH16Dx7aMOZawP5aBQW9gkOLo+fsicdl9sz1Gv7SEr5AcD48S
aq/v7h56rgJKihcrdv6sVIkkLE8/trKnToyokZf7KcZ7XC25y2a2t6hbElGFtQl+Ynhw/qlqYLYd
DnkM/crqJIByw5c/8nerQyIKx+u2DISCLIBrQYoIwOula9+ZEsuK1V6ADJHgJgg2SMX6OBE1/yWD
LfJ6v9r9jv6ly0UsH8SIU653DtmadsWOLB2jutXsMq7Aqqz30XpN69QH4kj3Io6wpJ9qzo6ysmD0
oyLQI+uUWnpp3Q+/QFesa1lQ2aOZ4W7+jQF5JyMV3pKdewlNWudLSDBaGOYKbeaP4NK75t98biGC
wWg5TbSYWGZizEqQXsP6JwSxeRV0mcy+rSDeJmAc61ZRpqPq5KM/p/9h3PFaTWwyI0PurKju7koS
CTxdccK+efrCh2gdC/1cacwG0Jp9VJkqyTkaGa9LKkPzY11aWOIv4x3kqdbQCtCev9eBCfHJxyYN
rJgWVqA=
-----END CERTIFICATE-----

Buypass Class 3 Root CA
=======================
-----BEGIN CERTIFICATE-----
MIIFWTCCA0GgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJOTzEdMBsGA1UECgwU
QnV5cGFzcyBBUy05ODMxNjMzMjcxIDAeBgNVBAMMF0J1eXBhc3MgQ2xhc3MgMyBSb290IENBMB4X
DTEwMTAyNjA4Mjg1OFoXDTQwMTAyNjA4Mjg1OFowTjELMAkGA1UEBhMCTk8xHTAbBgNVBAoMFEJ1
eXBhc3MgQVMtOTgzMTYzMzI3MSAwHgYDVQQDDBdCdXlwYXNzIENsYXNzIDMgUm9vdCBDQTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKXaCpUWUOOV8l6ddjEGMnqb8RB2uACatVI2zSRH
sJ8YZLya9vrVediQYkwiL944PdbgqOkcLNt4EemOaFEVcsfzM4fkoF0LXOBXByow9c3EN3coTRiR
5r/VUv1xLXA+58bEiuPwKAv0dpihi4dVsjoT/Lc+JzeOIuOoTyrvYLs9tznDDgFHmV0ST9tD+leh
7fmdvhFHJlsTmKtdFoqwNxxXnUX/iJY2v7vKB3tvh2PX0DJq1l1sDPGzbjniazEuOQAnFN44wOwZ
ZoYS6J1yFhNkUsepNxz9gjDthBgd9K5c/3ATAOux9TN6S9ZV+AWNS2mw9bMoNlwUxFFzTWsL8TQH
2xc519woe2v1n/MuwU8XKhDzzMro6/1rqy6any2CbgTUUgGTLT2G/H783+9CHaZr77kgxve9oKeV
/afmiSTYzIw0bOIjL9kSGiG5VZFvC5F5GQytQIgLcOJ60g7YaEi7ghM5EFjp2CoHxhLbWNvSO1UQ
RwUVZ2J+GGOmRj8JDlQyXr8NYnon74Do29lLBlo3WiXQCBJ31G8JUJc9yB3D34xFMFbG02SrZvPA
Xpacw8Tvw3xrizp5f7NJzz3iiZ+gMEuFuZyUJHmPfWupRWgPK9Dx2hzLabjKSWJtyNBjYt1gD1iq
j6G8BaVmos8bdrKEZLFMOVLAMLrwjEsCsLa3AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFEe4zf/lb+74suwvTg75JbCOPGvDMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsF
AAOCAgEAACAjQTUEkMJAYmDv4jVM1z+s4jSQuKFvdvoWFqRINyzpkMLyPPgKn9iB5btb2iUspKdV
cSQy9sgL8rxq+JOssgfCX5/bzMiKqr5qb+FJEMwx14C7u8jYog5kV+qi9cKpMRXSIGrs/CIBKM+G
uIAeqcwRpTzyFrNHnfzSgCHEy9BHcEGhyoMZCCxt8l13nIoUE9Q2HJLw5QY33KbmkJs4j1xrG0aG
Q0JfPgEHU1RdZX33inOhmlRaHylDFCfChQ+1iHsaO5S3HWCntZznKWlXWpuTekMwGwPXYshApqr8
ZORK15FTAaggiG6cX0S5y2CBNOxv033aSF/rtJC8LakcC6wc1aJoIIAE1vyxjy+7SjENSoYc6+I2
KSb12tjE8nVhz36udmNKekBlk4f4HoCMhuWG1o8O/FMsYOgWYRqiPkN7zTlgVGr18okmAWiDSKIz
6MkEkbIRNBE+6tBDGR8Dk5AM/1E9V/RBbuHLoL7ryWPNbczk+DaqaJ3tvV2XcEQNtg413OEMXbug
UZTLfhbrES+jkkXITHHZvMmZUldGL1DPvTVp9D0VzgalLA8+9oG6lLvDu79leNKGef9JOxqDDPDe
eOzI8k1MGt6CKfjBWtrt7uYnXuhF0J0cUahoq0Tj0Itq4/g7u9xN12TyUb7mqqta6THuBrxzvxNi
Cp/HuZc=
-----END CERTIFICATE-----

T-TeleSec GlobalRoot Class 3
============================
-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UEBhMCREUxKzApBgNVBAoM
IlQtU3lzdGVtcyBFbnRlcnByaXNlIFNlcnZpY2VzIEdtYkgxHzAdBgNVBAsMFlQtU3lzdGVtcyBU
cnVzdCBDZW50ZXIxJTAjBgNVBAMMHFQtVGVsZVNlYyBHbG9iYWxSb290IENsYXNzIDMwHhcNMDgx
MDAxMTAyOTU2WhcNMzMxMDAxMjM1OTU5WjCBgjELMAkGA1UEBhMCREUxKzApBgNVBAoMIlQtU3lz
dGVtcyBFbnRlcnByaXNlIFNlcnZpY2VzIEdtYkgxHzAdBgNVBAsMFlQtU3lzdGVtcyBUcnVzdCBD
ZW50ZXIxJTAjBgNVBAMMHFQtVGVsZVNlYyBHbG9iYWxSb290IENsYXNzIDMwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC9dZPwYiJvJK7genasfb3ZJNW4t/zN8ELg63iIVl6bmlQdTQyK
9tPPcPRStdiTBONGhnFBSivwKixVA9ZIw+A5OO3yXDw/RLyTPWGrTs0NvvAgJ1gORH8EGoel15YU
NpDQSXuhdfsaa3Ox+M6pCSzyU9XDFES4hqX2iys52qMzVNn6chr3IhUciJFrf2blw2qAsCTz34ZF
iP0Zf3WHHx+xGwpzJFu5ZeAsVMhg02YXP+HMVDNzkQI6pn97djmiH5a2OK61yJN0HZ65tOVgnS9W
0eDrXltMEnAMbEQgqxHY9Bn20pxSN+f6tsIxO0rUFJmtxxr1XV/6B7h8DR/Wgx6zAgMBAAGjQjBA
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBS1A/d2O2GCahKqGFPr
AyGUv/7OyjANBgkqhkiG9w0BAQsFAAOCAQEAVj3vlNW92nOyWL6ukK2YJ5f+AbGwUgC4TeQbIXQb
fsDuXmkqJa9c1h3a0nnJ85cp4IaH3gRZD/FZ1GSFS5mvJQQeyUapl96Cshtwn5z2r3Ex3XsFpSzT
ucpH9sry9uetuUg/vBa3wW306gmv7PO15wWeph6KU1HWk4HMdJP2udqmJQV0eVp+QD6CSyYRMG7h
P0HHRwA11fXT91Q+gT3aSWqas+8QPebrb9HIIkfLzM8BMZLZGOMivgkeGj5asuRrDFR6fUNOuIml
e9eiPZaGzPImNC1qkp2aGtAw4l1OBLBfiyB+d8E9lYLRRpo7PHi4b6HQDWSieB4pTpPDpFQUWw==
-----END CERTIFICATE-----

D-TRUST Root Class 3 CA 2 2009
==============================
-----BEGIN CERTIFICATE-----
MIIEMzCCAxugAwIBAgIDCYPzMA0GCSqGSIb3DQEBCwUAME0xCzAJBgNVBAYTAkRFMRUwEwYDVQQK
DAxELVRydXN0IEdtYkgxJzAlBgNVBAMMHkQtVFJVU1QgUm9vdCBDbGFzcyAzIENBIDIgMjAwOTAe
Fw0wOTExMDUwODM1NThaFw0yOTExMDUwODM1NThaME0xCzAJBgNVBAYTAkRFMRUwEwYDVQQKDAxE
LVRydXN0IEdtYkgxJzAlBgNVBAMMHkQtVFJVU1QgUm9vdCBDbGFzcyAzIENBIDIgMjAwOTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANOySs96R+91myP6Oi/WUEWJNTrGa9v+2wBoqOAD
ER03UAifTUpolDWzU9GUY6cgVq/eUXjsKj3zSEhQPgrfRlWLJ23DEE0NkVJD2IfgXU42tSHKXzlA
BF9bfsyjxiupQB7ZNoTWSPOSHjRGICTBpFGOShrvUD9pXRl/RcPHAY9RySPocq60vFYJfxLLHLGv
KZAKyVXMD9O0Gu1HNVpK7ZxzBCHQqr0ME7UAyiZsxGsMlFqVlNpQmvH/pStmMaTJOKDfHR+4CS7z
p+hnUquVH+BGPtikw8paxTGA6Eian5Rp/hnd2HN8gcqW3o7tszIFZYQ05ub9VxC1X3a/L7AQDcUC
AwEAAaOCARowggEWMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFP3aFMSfMN4hvR5COfyrYyNJ
4PGEMA4GA1UdDwEB/wQEAwIBBjCB0wYDVR0fBIHLMIHIMIGAoH6gfIZ6bGRhcDovL2RpcmVjdG9y
eS5kLXRydXN0Lm5ldC9DTj1ELVRSVVNUJTIwUm9vdCUyMENsYXNzJTIwMyUyMENBJTIwMiUyMDIw
MDksTz1ELVRydXN0JTIwR21iSCxDPURFP2NlcnRpZmljYXRlcmV2b2NhdGlvbmxpc3QwQ6BBoD+G
PWh0dHA6Ly93d3cuZC10cnVzdC5uZXQvY3JsL2QtdHJ1c3Rfcm9vdF9jbGFzc18zX2NhXzJfMjAw
OS5jcmwwDQYJKoZIhvcNAQELBQADggEBAH+X2zDI36ScfSF6gHDOFBJpiBSVYEQBrLLpME+bUMJm
2H6NMLVwMeniacfzcNsgFYbQDfC+rAF1hM5+n02/t2A7nPPKHeJeaNijnZflQGDSNiH+0LS4F9p0
o3/U37CYAqxva2ssJSRyoWXuJVrl5jLn8t+rSfrzkGkj2wTZ51xY/GXUl77M/C4KzCUqNQT4YJEV
dT1B/yMfGchs64JTBKbkTCJNjYy6zltz7GRUUG3RnFX7acM2w4y8PIWmawomDeCTmGCufsYkl4ph
X5GOZpIJhzbNi5stPvZR1FDUWSi9g/LMKHtThm3YJohw1+qRzT65ysCQblrGXnRl11z+o+I=
-----END CERTIFICATE-----

D-TRUST Root Class 3 CA 2 EV 2009
=================================
-----BEGIN CERTIFICATE-----
MIIEQzCCAyugAwIBAgIDCYP0MA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAkRFMRUwEwYDVQQK
DAxELVRydXN0IEdtYkgxKjAoBgNVBAMMIUQtVFJVU1QgUm9vdCBDbGFzcyAzIENBIDIgRVYgMjAw
OTAeFw0wOTExMDUwODUwNDZaFw0yOTExMDUwODUwNDZaMFAxCzAJBgNVBAYTAkRFMRUwEwYDVQQK
DAxELVRydXN0IEdtYkgxKjAoBgNVBAMMIUQtVFJVU1QgUm9vdCBDbGFzcyAzIENBIDIgRVYgMjAw
OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJnxhDRwui+3MKCOvXwEz75ivJn9gpfS
egpnljgJ9hBOlSJzmY3aFS3nBfwZcyK3jpgAvDw9rKFs+9Z5JUut8Mxk2og+KbgPCdM03TP1YtHh
zRnp7hhPTFiu4h7WDFsVWtg6uMQYZB7jM7K1iXdODL/ZlGsTl28So/6ZqQTMFexgaDbtCHu39b+T
7WYxg4zGcTSHThfqr4uRjRxWQa4iN1438h3Z0S0NL2lRp75mpoo6Kr3HGrHhFPC+Oh25z1uxav60
sUYgovseO3Dvk5h9jHOW8sXvhXCtKSb8HgQ+HKDYD8tSg2J87otTlZCpV6LqYQXY+U3EJ/pure35
11H3a6UCAwEAAaOCASQwggEgMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNOUikxiEyoZLsyv
cop9NteaHNxnMA4GA1UdDwEB/wQEAwIBBjCB3QYDVR0fBIHVMIHSMIGHoIGEoIGBhn9sZGFwOi8v
ZGlyZWN0b3J5LmQtdHJ1c3QubmV0L0NOPUQtVFJVU1QlMjBSb290JTIwQ2xhc3MlMjAzJTIwQ0El
MjAyJTIwRVYlMjAyMDA5LE89RC1UcnVzdCUyMEdtYkgsQz1ERT9jZXJ0aWZpY2F0ZXJldm9jYXRp
b25saXN0MEagRKBChkBodHRwOi8vd3d3LmQtdHJ1c3QubmV0L2NybC9kLXRydXN0X3Jvb3RfY2xh
c3NfM19jYV8yX2V2XzIwMDkuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQA07XtaPKSUiO8aEXUHL7P+
PPoeUSbrh/Yp3uDx1MYkCenBz1UbtDDZzhr+BlGmFaQt77JLvyAoJUnRpjZ3NOhk31KxEcdzes05
nsKtjHEh8lprr988TlWvsoRlFIm5d8sqMb7Po23Pb0iUMkZv53GMoKaEGTcH8gNFCSuGdXzfX2lX
ANtu2KZyIktQ1HWYVt+3GP9DQ1CuekR78HlR10M9p9OB0/DJT7naxpeG0ILD5EJt/rDiZE4OJudA
NCa1CInXCGNjOCd1HjPqbqjdn5lPdE2BiYBL3ZqXKVwvvoFBuYz/6n1gBp7N1z3TLqMVvKjmJuVv
w9y4AyHqnxbxLFS1
-----END CERTIFICATE-----

CA Disig Root R2
================
-----BEGIN CERTIFICATE-----
MIIFaTCCA1GgAwIBAgIJAJK4iNuwisFjMA0GCSqGSIb3DQEBCwUAMFIxCzAJBgNVBAYTAlNLMRMw
EQYDVQQHEwpCcmF0aXNsYXZhMRMwEQYDVQQKEwpEaXNpZyBhLnMuMRkwFwYDVQQDExBDQSBEaXNp
ZyBSb290IFIyMB4XDTEyMDcxOTA5MTUzMFoXDTQyMDcxOTA5MTUzMFowUjELMAkGA1UEBhMCU0sx
EzARBgNVBAcTCkJyYXRpc2xhdmExEzARBgNVBAoTCkRpc2lnIGEucy4xGTAXBgNVBAMTEENBIERp
c2lnIFJvb3QgUjIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCio8QACdaFXS1tFPbC
w3OeNcJxVX6B+6tGUODBfEl45qt5WDza/3wcn9iXAng+a0EE6UG9vgMsRfYvZNSrXaNHPWSb6Wia
xswbP7q+sos0Ai6YVRn8jG+qX9pMzk0DIaPY0jSTVpbLTAwAFjxfGs3Ix2ymrdMxp7zo5eFm1tL7
A7RBZckQrg4FY8aAamkw/dLukO8NJ9+flXP04SXabBbeQTg06ov80egEFGEtQX6sx3dOy1FU+16S
GBsEWmjGycT6txOgmLcRK7fWV8x8nhfRyyX+hk4kLlYMeE2eARKmK6cBZW58Yh2EhN/qwGu1pSqV
g8NTEQxzHQuyRpDRQjrOQG6Vrf/GlK1ul4SOfW+eioANSW1z4nuSHsPzwfPrLgVv2RvPN3YEyLRa
5Beny912H9AZdugsBbPWnDTYltxhh5EF5EQIM8HauQhl1K6yNg3ruji6DOWbnuuNZt2Zz9aJQfYE
koopKW1rOhzndX0CcQ7zwOe9yxndnWCywmZgtrEE7snmhrmaZkCo5xHtgUUDi/ZnWejBBhG93c+A
Ak9lQHhcR1DIm+YfgXvkRKhbhZri3lrVx/k6RGZL5DJUfORsnLMOPReisjQS1n6yqEm70XooQL6i
Fh/f5DcfEXP7kAplQ6INfPgGAVUzfbANuPT1rqVCV3w2EYx7XsQDnYx5nQIDAQABo0IwQDAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUtZn4r7CU9eMg1gqtzk5WpC5u
Qu0wDQYJKoZIhvcNAQELBQADggIBACYGXnDnZTPIgm7ZnBc6G3pmsgH2eDtpXi/q/075KMOYKmFM
tCQSin1tERT3nLXK5ryeJ45MGcipvXrA1zYObYVybqjGom32+nNjf7xueQgcnYqfGopTpti72TVV
sRHFqQOzVju5hJMiXn7B9hJSi+osZ7z+Nkz1uM/Rs0mSO9MpDpkblvdhuDvEK7Z4bLQjb/D907Je
dR+Zlais9trhxTF7+9FGs9K8Z7RiVLoJ92Owk6Ka+elSLotgEqv89WBW7xBci8QaQtyDW2QOy7W8
1k/BfDxujRNt+3vrMNDcTa/F1balTFtxyegxvug4BkihGuLq0t4SOVga/4AOgnXmt8kHbA7v/zjx
mHHEt38OFdAlab0inSvtBfZGR6ztwPDUO+Ls7pZbkBNOHlY667DvlruWIxG68kOGdGSVyCh13x01
utI3gzhTODY7z2zp+WsO0PsE6E9312UBeIYMej4hYvF/Y3EMyZ9E26gnonW+boE+18DrG5gPcFw0
sorMwIUY6256s/daoQe/qUKS82Ail+QUoQebTnbAjn39pCXHR+3/H3OszMOl6W8KjptlwlCFtaOg
UxLMVYdh84GuEEZhvUQhuMI9dM9+JDX6HAcOmz0iyu8xL4ysEr3vQCj8KWefshNPZiTEUxnpHikV
7+ZtsH8tZ/3zbBt1RqPlShfppNcL
-----END CERTIFICATE-----

ACCVRAIZ1
=========
-----BEGIN CERTIFICATE-----
MIIH0zCCBbugAwIBAgIIXsO3pkN/pOAwDQYJKoZIhvcNAQEFBQAwQjESMBAGA1UEAwwJQUNDVlJB
SVoxMRAwDgYDVQQLDAdQS0lBQ0NWMQ0wCwYDVQQKDARBQ0NWMQswCQYDVQQGEwJFUzAeFw0xMTA1
MDUwOTM3MzdaFw0zMDEyMzEwOTM3MzdaMEIxEjAQBgNVBAMMCUFDQ1ZSQUlaMTEQMA4GA1UECwwH
UEtJQUNDVjENMAsGA1UECgwEQUNDVjELMAkGA1UEBhMCRVMwggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQCbqau/YUqXry+XZpp0X9DZlv3P4uRm7x8fRzPCRKPfmt4ftVTdFXxpNRFvu8gM
jmoYHtiP2Ra8EEg2XPBjs5BaXCQ316PWywlxufEBcoSwfdtNgM3802/J+Nq2DoLSRYWoG2ioPej0
RGy9ocLLA76MPhMAhN9KSMDjIgro6TenGEyxCQ0jVn8ETdkXhBilyNpAlHPrzg5XPAOBOp0KoVdD
aaxXbXmQeOW1tDvYvEyNKKGno6e6Ak4l0Squ7a4DIrhrIA8wKFSVf+DuzgpmndFALW4ir50awQUZ
0m/A8p/4e7MCQvtQqR0tkw8jq8bBD5L/0KIV9VMJcRz/RROE5iZe+OCIHAr8Fraocwa48GOEAqDG
WuzndN9wrqODJerWx5eHk6fGioozl2A3ED6XPm4pFdahD9GILBKfb6qkxkLrQaLjlUPTAYVtjrs7
8yM2x/474KElB0iryYl0/wiPgL/AlmXz7uxLaL2diMMxs0Dx6M/2OLuc5NF/1OVYm3z61PMOm3WR
5LpSLhl+0fXNWhn8ugb2+1KoS5kE3fj5tItQo05iifCHJPqDQsGH+tUtKSpacXpkatcnYGMN285J
9Y0fkIkyF/hzQ7jSWpOGYdbhdQrqeWZ2iE9x6wQl1gpaepPluUsXQA+xtrn13k/c4LOsOxFwYIRK
Q26ZIMApcQrAZQIDAQABo4ICyzCCAscwfQYIKwYBBQUHAQEEcTBvMEwGCCsGAQUFBzAChkBodHRw
Oi8vd3d3LmFjY3YuZXMvZmlsZWFkbWluL0FyY2hpdm9zL2NlcnRpZmljYWRvcy9yYWl6YWNjdjEu
Y3J0MB8GCCsGAQUFBzABhhNodHRwOi8vb2NzcC5hY2N2LmVzMB0GA1UdDgQWBBTSh7Tj3zcnk1X2
VuqB5TbMjB4/vTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNKHtOPfNyeTVfZW6oHlNsyM
Hj+9MIIBcwYDVR0gBIIBajCCAWYwggFiBgRVHSAAMIIBWDCCASIGCCsGAQUFBwICMIIBFB6CARAA
QQB1AHQAbwByAGkAZABhAGQAIABkAGUAIABDAGUAcgB0AGkAZgBpAGMAYQBjAGkA8wBuACAAUgBh
AO0AegAgAGQAZQAgAGwAYQAgAEEAQwBDAFYAIAAoAEEAZwBlAG4AYwBpAGEAIABkAGUAIABUAGUA
YwBuAG8AbABvAGcA7QBhACAAeQAgAEMAZQByAHQAaQBmAGkAYwBhAGMAaQDzAG4AIABFAGwAZQBj
AHQAcgDzAG4AaQBjAGEALAAgAEMASQBGACAAUQA0ADYAMAAxADEANQA2AEUAKQAuACAAQwBQAFMA
IABlAG4AIABoAHQAdABwADoALwAvAHcAdwB3AC4AYQBjAGMAdgAuAGUAczAwBggrBgEFBQcCARYk
aHR0cDovL3d3dy5hY2N2LmVzL2xlZ2lzbGFjaW9uX2MuaHRtMFUGA1UdHwROMEwwSqBIoEaGRGh0
dHA6Ly93d3cuYWNjdi5lcy9maWxlYWRtaW4vQXJjaGl2b3MvY2VydGlmaWNhZG9zL3JhaXphY2N2
MV9kZXIuY3JsMA4GA1UdDwEB/wQEAwIBBjAXBgNVHREEEDAOgQxhY2N2QGFjY3YuZXMwDQYJKoZI
hvcNAQEFBQADggIBAJcxAp/n/UNnSEQU5CmH7UwoZtCPNdpNYbdKl02125DgBS4OxnnQ8pdpD70E
R9m+27Up2pvZrqmZ1dM8MJP1jaGo/AaNRPTKFpV8M9xii6g3+CfYCS0b78gUJyCpZET/LtZ1qmxN
YEAZSUNUY9rizLpm5U9EelvZaoErQNV/+QEnWCzI7UiRfD+mAM/EKXMRNt6GGT6d7hmKG9Ww7Y49
nCrADdg9ZuM8Db3VlFzi4qc1GwQA9j9ajepDvV+JHanBsMyZ4k0ACtrJJ1vnE5Bc5PUzolVt3OAJ
TS+xJlsndQAJxGJ3KQhfnlmstn6tn1QwIgPBHnFk/vk4CpYY3QIUrCPLBhwepH2NDd4nQeit2hW3
sCPdK6jT2iWH7ehVRE2I9DZ+hJp4rPcOVkkO1jMl1oRQQmwgEh0q1b688nCBpHBgvgW1m54ERL5h
I6zppSSMEYCUWqKiuUnSwdzRp+0xESyeGabu4VXhwOrPDYTkF7eifKXeVSUG7szAh1xA2syVP1Xg
Nce4hL60Xc16gwFy7ofmXx2utYXGJt/mwZrpHgJHnyqobalbz+xFd3+YJ5oyXSrjhO7FmGYvliAd
3djDJ9ew+f7Zfc3Qn48LFFhRny+Lwzgt3uiP1o2HpPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3p
EfbRD0tVNEYqi4Y7
-----END CERTIFICATE-----

TWCA Global Root CA
===================
-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgICDL4wDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVFcxEjAQBgNVBAoT
CVRBSVdBTi1DQTEQMA4GA1UECxMHUm9vdCBDQTEcMBoGA1UEAxMTVFdDQSBHbG9iYWwgUm9vdCBD
QTAeFw0xMjA2MjcwNjI4MzNaFw0zMDEyMzExNTU5NTlaMFExCzAJBgNVBAYTAlRXMRIwEAYDVQQK
EwlUQUlXQU4tQ0ExEDAOBgNVBAsTB1Jvb3QgQ0ExHDAaBgNVBAMTE1RXQ0EgR2xvYmFsIFJvb3Qg
Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCwBdvI64zEbooh745NnHEKH1Jw7W2C
nJfF10xORUnLQEK1EjRsGcJ0pDFfhQKX7EMzClPSnIyOt7h52yvVavKOZsTuKwEHktSz0ALfUPZV
r2YOy+BHYC8rMjk1Ujoog/h7FsYYuGLWRyWRzvAZEk2tY/XTP3VfKfChMBwqoJimFb3u/Rk28OKR
Q4/6ytYQJ0lM793B8YVwm8rqqFpD/G2Gb3PpN0Wp8DbHzIh1HrtsBv+baz4X7GGqcXzGHaL3SekV
tTzWoWH1EfcFbx39Eb7QMAfCKbAJTibc46KokWofwpFFiFzlmLhxpRUZyXx1EcxwdE8tmx2RRP1W
KKD+u4ZqyPpcC1jcxkt2yKsi2XMPpfRaAok/T54igu6idFMqPVMnaR1sjjIsZAAmY2E2TqNGtz99
sy2sbZCilaLOz9qC5wc0GZbpuCGqKX6mOL6OKUohZnkfs8O1CWfe1tQHRvMq2uYiN2DLgbYPoA/p
yJV/v1WRBXrPPRXAb94JlAGD1zQbzECl8LibZ9WYkTunhHiVJqRaCPgrdLQABDzfuBSO6N+pjWxn
kjMdwLfS7JLIvgm/LCkFbwJrnu+8vyq8W8BQj0FwcYeyTbcEqYSjMq+u7msXi7Kx/mzhkIyIqJdI
zshNy/MGz19qCkKxHh53L46g5pIOBvwFItIm4TFRfTLcDwIDAQABoyMwITAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAXzSBdu+WHdXltdkCY4QWwa6g
cFGn90xHNcgL1yg9iXHZqjNB6hQbbCEAwGxCGX6faVsgQt+i0trEfJdLjbDorMjupWkEmQqSpqsn
LhpNgb+E1HAerUf+/UqdM+DyucRFCCEK2mlpc3INvjT+lIutwx4116KD7+U4x6WFH6vPNOw/KP4M
8VeGTslV9xzU2KV9Bnpv1d8Q34FOIWWxtuEXeZVFBs5fzNxGiWNoRI2T9GRwoD2dKAXDOXC4Ynsg
/eTb6QihuJ49CcdP+yz4k3ZB3lLg4VfSnQO8d57+nile98FRYB/e2guyLXW3Q0iT5/Z5xoRdgFlg
lPx4mI88k1HtQJAH32RjJMtOcQWh15QaiDLxInQirqWm2BJpTGCjAu4r7NRjkgtevi92a6O2JryP
A9gK8kxkRr05YuWW6zRjESjMlfGt7+/cgFhI6Uu46mWs6fyAtbXIRfmswZ/ZuepiiI7E8UuDEq3m
i4TWnsLrgxifarsbJGAzcMzs9zLzXNl5fe+epP7JI8Mk7hWSsT2RTyaGvWZzJBPqpK5jwa19hAM8
EHiGG3njxPPyBJUgriOCxLM6AGK/5jYk4Ve6xx6QddVfP5VhK8E7zeWzaGHQRiapIVJpLesux+t3
zqY6tQMzT3bR51xUAV3LePTJDL/PEo4XLSNolOer/qmyKwbQBM0=
-----END CERTIFICATE-----

TeliaSonera Root CA v1
======================
-----BEGIN CERTIFICATE-----
MIIFODCCAyCgAwIBAgIRAJW+FqD3LkbxezmCcvqLzZYwDQYJKoZIhvcNAQEFBQAwNzEUMBIGA1UE
CgwLVGVsaWFTb25lcmExHzAdBgNVBAMMFlRlbGlhU29uZXJhIFJvb3QgQ0EgdjEwHhcNMDcxMDE4
MTIwMDUwWhcNMzIxMDE4MTIwMDUwWjA3MRQwEgYDVQQKDAtUZWxpYVNvbmVyYTEfMB0GA1UEAwwW
VGVsaWFTb25lcmEgUm9vdCBDQSB2MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMK+
6yfwIaPzaSZVfp3FVRaRXP3vIb9TgHot0pGMYzHw7CTww6XScnwQbfQ3t+XmfHnqjLWCi65ItqwA
3GV17CpNX8GH9SBlK4GoRz6JI5UwFpB/6FcHSOcZrr9FZ7E3GwYq/t75rH2D+1665I+XZ75Ljo1k
B1c4VWk0Nj0TSO9P4tNmHqTPGrdeNjPUtAa9GAH9d4RQAEX1jF3oI7x+/jXh7VB7qTCNGdMJjmhn
Xb88lxhTuylixcpecsHHltTbLaC0H2kD7OriUPEMPPCs81Mt8Bz17Ww5OXOAFshSsCPN4D7c3TxH
oLs1iuKYaIu+5b9y7tL6pe0S7fyYGKkmdtwoSxAgHNN/Fnct7W+A90m7UwW7XWjH1Mh1Fj+JWov3
F0fUTPHSiXk+TT2YqGHeOh7S+F4D4MHJHIzTjU3TlTazN19jY5szFPAtJmtTfImMMsJu7D0hADnJ
oWjiUIMusDor8zagrC/kb2HCUQk5PotTubtn2txTuXZZNp1D5SDgPTJghSJRt8czu90VL6R4pgd7
gUY2BIbdeTXHlSw7sKMXNeVzH7RcWe/a6hBle3rQf5+ztCo3O3CLm1u5K7fsslESl1MpWtTwEhDc
TwK7EpIvYtQ/aUN8Ddb8WHUBiJ1YFkveupD/RwGJBmr2X7KQarMCpgKIv7NHfirZ1fpoeDVNAgMB
AAGjPzA9MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgEGMB0GA1UdDgQWBBTwj1k4ALP1j5qW
DNXr+nuqF+gTEjANBgkqhkiG9w0BAQUFAAOCAgEAvuRcYk4k9AwI//DTDGjkk0kiP0Qnb7tt3oNm
zqjMDfz1mgbldxSR651Be5kqhOX//CHBXfDkH1e3damhXwIm/9fH907eT/j3HEbAek9ALCI18Bmx
0GtnLLCo4MBANzX2hFxc469CeP6nyQ1Q6g2EdvZR74NTxnr/DlZJLo961gzmJ1TjTQpgcmLNkQfW
pb/ImWvtxBnmq0wROMVvMeJuScg/doAmAyYp4Db29iBT4xdwNBedY2gea+zDTYa4EzAvXUYNR0PV
G6pZDrlcjQZIrXSHX8f8MVRBE+LHIQ6e4B4N4cB7Q4WQxYpYxmUKeFfyxiMPAdkgS94P+5KFdSpc
c41teyWRyu5FrgZLAMzTsVlQ2jqIOylDRl6XK1TOU2+NSueW+r9xDkKLfP0ooNBIytrEgUy7onOT
JsjrDNYmiLbAJM+7vVvrdX3pCI6GMyx5dwlppYn8s3CQh3aP0yK7Qs69cwsgJirQmz1wHiRszYd2
qReWt88NkvuOGKmYSdGe/mBEciG5Ge3C9THxOUiIkCR1VBatzvT4aRRkOfujuLpwQMcnHL/EVlP6
Y2XQ8xwOFvVrhlhNGNTkDY6lnVuR3HYkUD/GKvvZt5y11ubQ2egZixVxSK236thZiNSQvxaz2ems
WWFUyBy6ysHK4bkgTI86k4mloMy/0/Z1pHWWbVY=
-----END CERTIFICATE-----

E-Tugra Certification Authority
===============================
-----BEGIN CERTIFICATE-----
MIIGSzCCBDOgAwIBAgIIamg+nFGby1MwDQYJKoZIhvcNAQELBQAwgbIxCzAJBgNVBAYTAlRSMQ8w
DQYDVQQHDAZBbmthcmExQDA+BgNVBAoMN0UtVHXEn3JhIEVCRyBCaWxpxZ9pbSBUZWtub2xvamls
ZXJpIHZlIEhpem1ldGxlcmkgQS7Fni4xJjAkBgNVBAsMHUUtVHVncmEgU2VydGlmaWthc3lvbiBN
ZXJrZXppMSgwJgYDVQQDDB9FLVR1Z3JhIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTEzMDMw
NTEyMDk0OFoXDTIzMDMwMzEyMDk0OFowgbIxCzAJBgNVBAYTAlRSMQ8wDQYDVQQHDAZBbmthcmEx
QDA+BgNVBAoMN0UtVHXEn3JhIEVCRyBCaWxpxZ9pbSBUZWtub2xvamlsZXJpIHZlIEhpem1ldGxl
cmkgQS7Fni4xJjAkBgNVBAsMHUUtVHVncmEgU2VydGlmaWthc3lvbiBNZXJrZXppMSgwJgYDVQQD
DB9FLVR1Z3JhIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEA4vU/kwVRHoViVF56C/UYB4Oufq9899SKa6VjQzm5S/fDxmSJPZQuVIBSOTkHS0vd
hQd2h8y/L5VMzH2nPbxHD5hw+IyFHnSOkm0bQNGZDbt1bsipa5rAhDGvykPL6ys06I+XawGb1Q5K
CKpbknSFQ9OArqGIW66z6l7LFpp3RMih9lRozt6Plyu6W0ACDGQXwLWTzeHxE2bODHnv0ZEoq1+g
ElIwcxmOj+GMB6LDu0rw6h8VqO4lzKRG+Bsi77MOQ7osJLjFLFzUHPhdZL3Dk14opz8n8Y4e0ypQ
BaNV2cvnOVPAmJ6MVGKLJrD3fY185MaeZkJVgkfnsliNZvcHfC425lAcP9tDJMW/hkd5s3kc91r0
E+xs+D/iWR+V7kI+ua2oMoVJl0b+SzGPWsutdEcf6ZG33ygEIqDUD13ieU/qbIWGvaimzuT6w+Gz
rt48Ue7LE3wBf4QOXVGUnhMMti6lTPk5cDZvlsouDERVxcr6XQKj39ZkjFqzAQqptQpHF//vkUAq
jqFGOjGY5RH8zLtJVor8udBhmm9lbObDyz51Sf6Pp+KJxWfXnUYTTjF2OySznhFlhqt/7x3U+Lzn
rFpct1pHXFXOVbQicVtbC/DP3KBhZOqp12gKY6fgDT+gr9Oq0n7vUaDmUStVkhUXU8u3Zg5mTPj5
dUyQ5xJwx0UCAwEAAaNjMGEwHQYDVR0OBBYEFC7j27JJ0JxUeVz6Jyr+zE7S6E5UMA8GA1UdEwEB
/wQFMAMBAf8wHwYDVR0jBBgwFoAULuPbsknQnFR5XPonKv7MTtLoTlQwDgYDVR0PAQH/BAQDAgEG
MA0GCSqGSIb3DQEBCwUAA4ICAQAFNzr0TbdF4kV1JI+2d1LoHNgQk2Xz8lkGpD4eKexd0dCrfOAK
kEh47U6YA5n+KGCRHTAduGN8qOY1tfrTYXbm1gdLymmasoR6d5NFFxWfJNCYExL/u6Au/U5Mh/jO
XKqYGwXgAEZKgoClM4so3O0409/lPun++1ndYYRP0lSWE2ETPo+Aab6TR7U1Q9Jauz1c77NCR807
VRMGsAnb/WP2OogKmW9+4c4bU2pEZiNRCHu8W1Ki/QY3OEBhj0qWuJA3+GbHeJAAFS6LrVE1Uweo
a2iu+U48BybNCAVwzDk/dr2l02cmAYamU9JgO3xDf1WKvJUawSg5TB9D0pH0clmKuVb8P7Sd2nCc
dlqMQ1DujjByTd//SffGqWfZbawCEeI6FiWnWAjLb1NBnEg4R2gz0dfHj9R0IdTDBZB6/86WiLEV
KV0jq9BgoRJP3vQXzTLlyb/IQ639Lo7xr+L0mPoSHyDYwKcMhcWQ9DstliaxLL5Mq+ux0orJ23gT
Dx4JnW2PAJ8C2sH6H3p6CcRK5ogql5+Ji/03X186zjhZhkuvcQu02PJwT58yE+Owp1fl2tpDy4Q0
8ijE6m30Ku/Ba3ba+367hTzSU8JNvnHhRdH9I2cNE3X7z2VnIp2usAnRCf8dNL/+I5c30jn6PQ0G
C7TbO6Orb1wdtn7os4I07QZcJA==
-----END CERTIFICATE-----

T-TeleSec GlobalRoot Class 2
============================
-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBgjELMAkGA1UEBhMCREUxKzApBgNVBAoM
IlQtU3lzdGVtcyBFbnRlcnByaXNlIFNlcnZpY2VzIEdtYkgxHzAdBgNVBAsMFlQtU3lzdGVtcyBU
cnVzdCBDZW50ZXIxJTAjBgNVBAMMHFQtVGVsZVNlYyBHbG9iYWxSb290IENsYXNzIDIwHhcNMDgx
MDAxMTA0MDE0WhcNMzMxMDAxMjM1OTU5WjCBgjELMAkGA1UEBhMCREUxKzApBgNVBAoMIlQtU3lz
dGVtcyBFbnRlcnByaXNlIFNlcnZpY2VzIEdtYkgxHzAdBgNVBAsMFlQtU3lzdGVtcyBUcnVzdCBD
ZW50ZXIxJTAjBgNVBAMMHFQtVGVsZVNlYyBHbG9iYWxSb290IENsYXNzIDIwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCqX9obX+hzkeXaXPSi5kfl82hVYAUdAqSzm1nzHoqvNK38DcLZ
SBnuaY/JIPwhqgcZ7bBcrGXHX+0CfHt8LRvWurmAwhiCFoT6ZrAIxlQjgeTNuUk/9k9uN0goOA/F
vudocP05l03Sx5iRUKrERLMjfTlH6VJi1hKTXrcxlkIF+3anHqP1wvzpesVsqXFP6st4vGCvx970
2cu+fjOlbpSD8DT6IavqjnKgP6TeMFvvhk1qlVtDRKgQFRzlAVfFmPHmBiiRqiDFt1MmUUOyCxGV
WOHAD3bZwI18gfNycJ5v/hqO2V81xrJvNHy+SE/iWjnX2J14np+GPgNeGYtEotXHAgMBAAGjQjBA
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBS/WSA2AHmgoCJrjNXy
YdK4LMuCSjANBgkqhkiG9w0BAQsFAAOCAQEAMQOiYQsfdOhyNsZt+U2e+iKo4YFWz827n+qrkRk4
r6p8FU3ztqONpfSO9kSpp+ghla0+AGIWiPACuvxhI+YzmzB6azZie60EI4RYZeLbK4rnJVM3YlNf
vNoBYimipidx5joifsFvHZVwIEoHNN/q/xWA5brXethbdXwFeilHfkCoMRN3zUA7tFFHei4R40cR
3p1m0IvVVGb6g1XqfMIpiRvpb7PO4gWEyS8+eIVibslfwXhjdFjASBgMmTnrpMwatXlajRWc2BQN
9noHV8cigwUtPJslJj0Ys6lDfMjIq2SPDqO/nBudMNva0Bkuqjzx+zOAduTNrRlPBSeOE6Fuwg==
-----END CERTIFICATE-----

Atos TrustedRoot 2011
=====================
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIIXDPLYixfszIwDQYJKoZIhvcNAQELBQAwPDEeMBwGA1UEAwwVQXRvcyBU
cnVzdGVkUm9vdCAyMDExMQ0wCwYDVQQKDARBdG9zMQswCQYDVQQGEwJERTAeFw0xMTA3MDcxNDU4
MzBaFw0zMDEyMzEyMzU5NTlaMDwxHjAcBgNVBAMMFUF0b3MgVHJ1c3RlZFJvb3QgMjAxMTENMAsG
A1UECgwEQXRvczELMAkGA1UEBhMCREUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCV
hTuXbyo7LjvPpvMpNb7PGKw+qtn4TaA+Gke5vJrf8v7MPkfoepbCJI419KkM/IL9bcFyYie96mvr
54rMVD6QUM+A1JX76LWC1BTFtqlVJVfbsVD2sGBkWXppzwO3bw2+yj5vdHLqqjAqc2K+SZFhyBH+
DgMq92og3AIVDV4VavzjgsG1xZ1kCWyjWZgHJ8cblithdHFsQ/H3NYkQ4J7sVaE3IqKHBAUsR320
HLliKWYoyrfhk/WklAOZuXCFteZI6o1Q/NnezG8HDt0Lcp2AMBYHlT8oDv3FdU9T1nSatCQujgKR
z3bFmx5VdJx4IbHwLfELn8LVlhgf8FQieowHAgMBAAGjfTB7MB0GA1UdDgQWBBSnpQaxLKYJYO7R
l+lwrrw7GWzbITAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFKelBrEspglg7tGX6XCuvDsZ
bNshMBgGA1UdIAQRMA8wDQYLKwYBBAGwLQMEAQEwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEB
CwUAA4IBAQAmdzTblEiGKkGdLD4GkGDEjKwLVLgfuXvTBznk+j57sj1O7Z8jvZfza1zv7v1Apt+h
k6EKhqzvINB5Ab149xnYJDE0BAGmuhWawyfc2E8PzBhj/5kPDpFrdRbhIfzYJsdHt6bPWHJxfrrh
TZVHO8mvbaG0weyJ9rQPOLXiZNwlz6bb65pcmaHFCN795trV1lpFDMS3wrUU77QR/w4VtfX128a9
61qn8FYiqTxlVMYVqL2Gns2Dlmh6cYGJ4Qvh6hEbaAjMaZ7snkGeRDImeuKHCnE96+RapNLbxc3G
3mB/ufNPRJLvKrcYPqcZ2Qt9sTdBQrC6YB3y/gkRsPCHe6ed
-----END CERTIFICATE-----

QuoVadis Root CA 1 G3
=====================
-----BEGIN CERTIFICATE-----
MIIFYDCCA0igAwIBAgIUeFhfLq0sGUvjNwc1NBMotZbUZZMwDQYJKoZIhvcNAQELBQAwSDELMAkG
A1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxHjAcBgNVBAMTFVF1b1ZhZGlzIFJv
b3QgQ0EgMSBHMzAeFw0xMjAxMTIxNzI3NDRaFw00MjAxMTIxNzI3NDRaMEgxCzAJBgNVBAYTAkJN
MRkwFwYDVQQKExBRdW9WYWRpcyBMaW1pdGVkMR4wHAYDVQQDExVRdW9WYWRpcyBSb290IENBIDEg
RzMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCgvlAQjunybEC0BJyFuTHK3C3kEakE
PBtVwedYMB0ktMPvhd6MLOHBPd+C5k+tR4ds7FtJwUrVu4/sh6x/gpqG7D0DmVIB0jWerNrwU8lm
PNSsAgHaJNM7qAJGr6Qc4/hzWHa39g6QDbXwz8z6+cZM5cOGMAqNF34168Xfuw6cwI2H44g4hWf6
Pser4BOcBRiYz5P1sZK0/CPTz9XEJ0ngnjybCKOLXSoh4Pw5qlPafX7PGglTvF0FBM+hSo+LdoIN
ofjSxxR3W5A2B4GbPgb6Ul5jxaYA/qXpUhtStZI5cgMJYr2wYBZupt0lwgNm3fME0UDiTouG9G/l
g6AnhF4EwfWQvTA9xO+oabw4m6SkltFi2mnAAZauy8RRNOoMqv8hjlmPSlzkYZqn0ukqeI1RPToV
7qJZjqlc3sX5kCLliEVx3ZGZbHqfPT2YfF72vhZooF6uCyP8Wg+qInYtyaEQHeTTRCOQiJ/GKubX
9ZqzWB4vMIkIG1SitZgj7Ah3HJVdYdHLiZxfokqRmu8hqkkWCKi9YSgxyXSthfbZxbGL0eUQMk1f
iyA6PEkfM4VZDdvLCXVDaXP7a3F98N/ETH3Goy7IlXnLc6KOTk0k+17kBL5yG6YnLUlamXrXXAkg
t3+UuU/xDRxeiEIbEbfnkduebPRq34wGmAOtzCjvpUfzUwIDAQABo0IwQDAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUo5fW816iEOGrRZ88F2Q87gFwnMwwDQYJKoZI
hvcNAQELBQADggIBABj6W3X8PnrHX3fHyt/PX8MSxEBd1DKquGrX1RUVRpgjpeaQWxiZTOOtQqOC
MTaIzen7xASWSIsBx40Bz1szBpZGZnQdT+3Btrm0DWHMY37XLneMlhwqI2hrhVd2cDMT/uFPpiN3
GPoajOi9ZcnPP/TJF9zrx7zABC4tRi9pZsMbj/7sPtPKlL92CiUNqXsCHKnQO18LwIE6PWThv6ct
Tr1NxNgpxiIY0MWscgKCP6o6ojoilzHdCGPDdRS5YCgtW2jgFqlmgiNR9etT2DGbe+m3nUvriBbP
+V04ikkwj+3x6xn0dxoxGE1nVGwvb2X52z3sIexe9PSLymBlVNFxZPT5pqOBMzYzcfCkeF9OrYMh
3jRJjehZrJ3ydlo28hP0r+AJx2EqbPfgna67hkooby7utHnNkDPDs3b69fBsnQGQ+p6Q9pxyz0fa
wx/kNSBT8lTR32GDpgLiJTjehTItXnOQUl1CxM49S+H5GYQd1aJQzEH7QRTDvdbJWqNjZgKAvQU6
O0ec7AAmTPWIUb+oI38YB7AL7YsmoWTTYUrrXJ/es69nA7Mf3W1daWhpq1467HxpvMc7hU6eFbm0
FU/DlXpY18ls6Wy58yljXrQs8C097Vpl4KlbQMJImYFtnh8GKjwStIsPm6Ik8KaN1nrgS7ZklmOV
hMJKzRwuJIczYOXD
-----END CERTIFICATE-----

QuoVadis Root CA 2 G3
=====================
-----BEGIN CERTIFICATE-----
MIIFYDCCA0igAwIBAgIURFc0JFuBiZs18s64KztbpybwdSgwDQYJKoZIhvcNAQELBQAwSDELMAkG
A1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxHjAcBgNVBAMTFVF1b1ZhZGlzIFJv
b3QgQ0EgMiBHMzAeFw0xMjAxMTIxODU5MzJaFw00MjAxMTIxODU5MzJaMEgxCzAJBgNVBAYTAkJN
MRkwFwYDVQQKExBRdW9WYWRpcyBMaW1pdGVkMR4wHAYDVQQDExVRdW9WYWRpcyBSb290IENBIDIg
RzMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQChriWyARjcV4g/Ruv5r+LrI3HimtFh
ZiFfqq8nUeVuGxbULX1QsFN3vXg6YOJkApt8hpvWGo6t/x8Vf9WVHhLL5hSEBMHfNrMWn4rjyduY
NM7YMxcoRvynyfDStNVNCXJJ+fKH46nafaF9a7I6JaltUkSs+L5u+9ymc5GQYaYDFCDy54ejiK2t
oIz/pgslUiXnFgHVy7g1gQyjO/Dh4fxaXc6AcW34Sas+O7q414AB+6XrW7PFXmAqMaCvN+ggOp+o
MiwMzAkd056OXbxMmO7FGmh77FOm6RQ1o9/NgJ8MSPsc9PG/Srj61YxxSscfrf5BmrODXfKEVu+l
V0POKa2Mq1W/xPtbAd0jIaFYAI7D0GoT7RPjEiuA3GfmlbLNHiJuKvhB1PLKFAeNilUSxmn1uIZo
L1NesNKqIcGY5jDjZ1XHm26sGahVpkUG0CM62+tlXSoREfA7T8pt9DTEceT/AFr2XK4jYIVz8eQQ
sSWu1ZK7E8EM4DnatDlXtas1qnIhO4M15zHfeiFuuDIIfR0ykRVKYnLP43ehvNURG3YBZwjgQQvD
6xVu+KQZ2aKrr+InUlYrAoosFCT5v0ICvybIxo/gbjh9Uy3l7ZizlWNof/k19N+IxWA1ksB8aRxh
lRbQ694Lrz4EEEVlWFA4r0jyWbYW8jwNkALGcC4BrTwV1wIDAQABo0IwQDAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU7edvdlq/YOxJW8ald7tyFnGbxD0wDQYJKoZI
hvcNAQELBQADggIBAJHfgD9DCX5xwvfrs4iP4VGyvD11+ShdyLyZm3tdquXK4Qr36LLTn91nMX66
AarHakE7kNQIXLJgapDwyM4DYvmL7ftuKtwGTTwpD4kWilhMSA/ohGHqPHKmd+RCroijQ1h5fq7K
pVMNqT1wvSAZYaRsOPxDMuHBR//47PERIjKWnML2W2mWeyAMQ0GaW/ZZGYjeVYg3UQt4XAoeo0L9
x52ID8DyeAIkVJOviYeIyUqAHerQbj5hLja7NQ4nlv1mNDthcnPxFlxHBlRJAHpYErAK74X9sbgz
dWqTHBLmYF5vHX/JHyPLhGGfHoJE+V+tYlUkmlKY7VHnoX6XOuYvHxHaU4AshZ6rNRDbIl9qxV6X
U/IyAgkwo1jwDQHVcsaxfGl7w/U2Rcxhbl5MlMVerugOXou/983g7aEOGzPuVBj+D77vfoRrQ+Nw
mNtddbINWQeFFSM51vHfqSYP1kjHs6Yi9TM3WpVHn3u6GBVv/9YUZINJ0gpnIdsPNWNgKCLjsZWD
zYWm3S8P52dSbrsvhXz1SnPnxT7AvSESBT/8twNJAlvIJebiVDj1eYeMHVOyToV7BjjHLPj4sHKN
JeV3UvQDHEimUF+IIDBu8oJDqz2XhOdT+yHBTw8imoa4WSr2Rz0ZiC3oheGe7IUIarFsNMkd7Egr
O3jtZsSOeWmD3n+M
-----END CERTIFICATE-----

QuoVadis Root CA 3 G3
=====================
-----BEGIN CERTIFICATE-----
MIIFYDCCA0igAwIBAgIULvWbAiin23r/1aOp7r0DoM8Sah0wDQYJKoZIhvcNAQELBQAwSDELMAkG
A1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxHjAcBgNVBAMTFVF1b1ZhZGlzIFJv
b3QgQ0EgMyBHMzAeFw0xMjAxMTIyMDI2MzJaFw00MjAxMTIyMDI2MzJaMEgxCzAJBgNVBAYTAkJN
MRkwFwYDVQQKExBRdW9WYWRpcyBMaW1pdGVkMR4wHAYDVQQDExVRdW9WYWRpcyBSb290IENBIDMg
RzMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCzyw4QZ47qFJenMioKVjZ/aEzHs286
IxSR/xl/pcqs7rN2nXrpixurazHb+gtTTK/FpRp5PIpM/6zfJd5O2YIyC0TeytuMrKNuFoM7pmRL
Mon7FhY4futD4tN0SsJiCnMK3UmzV9KwCoWdcTzeo8vAMvMBOSBDGzXRU7Ox7sWTaYI+FrUoRqHe
6okJ7UO4BUaKhvVZR74bbwEhELn9qdIoyhA5CcoTNs+cra1AdHkrAj80//ogaX3T7mH1urPnMNA3
I4ZyYUUpSFlob3emLoG+B01vr87ERRORFHAGjx+f+IdpsQ7vw4kZ6+ocYfx6bIrc1gMLnia6Et3U
VDmrJqMz6nWB2i3ND0/kA9HvFZcba5DFApCTZgIhsUfei5pKgLlVj7WiL8DWM2fafsSntARE60f7
5li59wzweyuxwHApw0BiLTtIadwjPEjrewl5qW3aqDCYz4ByA4imW0aucnl8CAMhZa634RylsSqi
Md5mBPfAdOhx3v89WcyWJhKLhZVXGqtrdQtEPREoPHtht+KPZ0/l7DxMYIBpVzgeAVuNVejH38DM
dyM0SXV89pgR6y3e7UEuFAUCf+D+IOs15xGsIs5XPd7JMG0QA4XN8f+MFrXBsj6IbGB/kE+V9/Yt
rQE5BwT6dYB9v0lQ7e/JxHwc64B+27bQ3RP+ydOc17KXqQIDAQABo0IwQDAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUxhfQvKjqAkPyGwaZXSuQILnXnOQwDQYJKoZI
hvcNAQELBQADggIBADRh2Va1EodVTd2jNTFGu6QHcrxfYWLopfsLN7E8trP6KZ1/AvWkyaiTt3px
KGmPc+FSkNrVvjrlt3ZqVoAh313m6Tqe5T72omnHKgqwGEfcIHB9UqM+WXzBusnIFUBhynLWcKzS
t/Ac5IYp8M7vaGPQtSCKFWGafoaYtMnCdvvMujAWzKNhxnQT5WvvoxXqA/4Ti2Tk08HS6IT7SdEQ
TXlm66r99I0xHnAUrdzeZxNMgRVhvLfZkXdxGYFgu/BYpbWcC/ePIlUnwEsBbTuZDdQdm2NnL9Du
DcpmvJRPpq3t/O5jrFc/ZSXPsoaP0Aj/uHYUbt7lJ+yreLVTubY/6CD50qi+YUbKh4yE8/nxoGib
Ih6BJpsQBJFxwAYf3KDTuVan45gtf4Od34wrnDKOMpTwATwiKp9Dwi7DmDkHOHv8XgBCH/MyJnmD
hPbl8MFREsALHgQjDFSlTC9JxUrRtm5gDWv8a4uFJGS3iQ6rJUdbPM9+Sb3H6QrG2vd+DhcI00iX
0HGS8A85PjRqHH3Y8iKuu2n0M7SmSFXRDw4m6Oy2Cy2nhTXN/VnIn9HNPlopNLk9hM6xZdRZkZFW
dSHBd575euFgndOtBBj0fOtek49TSiIp+EgrPk2GrFt/ywaZWWDYWGWVjUTR939+J399roD1B0y2
PpxxVJkES/1Y+Zj0
-----END CERTIFICATE-----

DigiCert Assured ID Root G2
===========================
-----BEGIN CERTIFICATE-----
MIIDljCCAn6gAwIBAgIQC5McOtY5Z+pnI7/Dr5r0SzANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQw
IgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgRzIwHhcNMTMwODAxMTIwMDAwWhcNMzgw
MTE1MTIwMDAwWjBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
ExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgRzIw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZ5ygvUj82ckmIkzTz+GoeMVSAn61UQbVH
35ao1K+ALbkKz3X9iaV9JPrjIgwrvJUXCzO/GU1BBpAAvQxNEP4HteccbiJVMWWXvdMX0h5i89vq
bFCMP4QMls+3ywPgym2hFEwbid3tALBSfK+RbLE4E9HpEgjAALAcKxHad3A2m67OeYfcgnDmCXRw
VWmvo2ifv922ebPynXApVfSr/5Vh88lAbx3RvpO704gqu52/clpWcTs/1PPRCv4o76Pu2ZmvA9OP
YLfykqGxvYmJHzDNw6YuYjOuFgJ3RFrngQo8p0Quebg/BLxcoIfhG69Rjs3sLPr4/m3wOnyqi+Rn
lTGNAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTO
w0q5mVXyuNtgv6l+vVa1lzan1jANBgkqhkiG9w0BAQsFAAOCAQEAyqVVjOPIQW5pJ6d1Ee88hjZv
0p3GeDgdaZaikmkuOGybfQTUiaWxMTeKySHMq2zNixya1r9I0jJmwYrA8y8678Dj1JGG0VDjA9tz
d29KOVPt3ibHtX2vK0LRdWLjSisCx1BL4GnilmwORGYQRI+tBev4eaymG+g3NJ1TyWGqolKvSnAW
hsI6yLETcDbYz+70CjTVW0z9B5yiutkBclzzTcHdDrEcDcRjvq30FPuJ7KJBDkzMyFdA0G4Dqs0M
jomZmWzwPDCvON9vvKO+KSAnq3T/EyJ43pdSVR6DtVQgA+6uwE9W3jfMw3+qBCe703e4YtsXfJwo
IhNzbM8m9Yop5w==
-----END CERTIFICATE-----

DigiCert Assured ID Root G3
===========================
-----BEGIN CERTIFICATE-----
MIICRjCCAc2gAwIBAgIQC6Fa+h3foLVJRK/NJKBs7DAKBggqhkjOPQQDAzBlMQswCQYDVQQGEwJV
UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYD
VQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgRzMwHhcNMTMwODAxMTIwMDAwWhcNMzgwMTE1
MTIwMDAwWjBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgRzMwdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAAQZ57ysRGXtzbg/WPuNsVepRC0FFfLvC/8QdJ+1YlJfZn4f5dwb
RXkLzMZTCp2NXQLZqVneAlr2lSoOjThKiknGvMYDOAdfVdp+CW7if17QRSAPWXYQ1qAk8C3eNvJs
KTmjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTL0L2p4ZgF
UaFNN6KDec6NHSrkhDAKBggqhkjOPQQDAwNnADBkAjAlpIFFAmsSS3V0T8gj43DydXLefInwz5Fy
YZ5eEJJZVrmDxxDnOOlYJjZ91eQ0hjkCMHw2U/Aw5WJjOpnitqM7mzT6HtoQknFekROn3aRukswy
1vUhZscv6pZjamVFkpUBtA==
-----END CERTIFICATE-----

DigiCert Global Root G2
=======================
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAw
HgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUx
MjAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
dy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI2/Ou8jqJ
kTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx1x7e/dfgy5SDN67sH0NO
3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQq2EGnI/yuum06ZIya7XzV+hdG82MHauV
BJVJ8zUtluNJbd134/tJS7SsVQepj5WztCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyM
UNGPHgm+F6HmIcr9g+UQvIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQAB
o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV5uNu
5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY1Yl9PMWLSn/pvtsr
F9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4NeF22d+mQrvHRAiGfzZ0JFrabA0U
WTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NGFdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBH
QRFXGU7Aj64GxJUTFy8bJZ918rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/
iyK5S9kJRaTepLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----

DigiCert Global Root G3
=======================
-----BEGIN CERTIFICATE-----
MIICPzCCAcWgAwIBAgIQBVVWvPJepDU1w6QP1atFcjAKBggqhkjOPQQDAzBhMQswCQYDVQQGEwJV
UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYD
VQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAw
MDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5k
aWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE3afZu4q4C/sLfyHS8L6+c/MzXRq8NOrexpu80JX28MzQC7phW1FGfp4tn+6O
YwwX7Adw9c+ELkCDnOg/QW07rdOkFFk2eJ0DQ+4QE2xy3q6Ip6FrtUPOZ9wj/wMco+I+o0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUs9tIpPmhxdiuNkHMEWNp
Yim8S8YwCgYIKoZIzj0EAwMDaAAwZQIxAK288mw/EkrRLTnDCgmXc/SINoyIJ7vmiI1Qhadj+Z4y
3maTD/HMsQmP3Wyr+mt/oAIwOWZbwmSNuJ5Q3KjVSaLtx9zRSX8XAbjIho9OjIgrqJqpisXRAL34
VOKa5Vt8sycX
-----END CERTIFICATE-----

DigiCert Trusted Root G4
========================
-----BEGIN CERTIFICATE-----
MIIFkDCCA3igAwIBAgIQBZsbV56OITLiOQe9p3d1XDANBgkqhkiG9w0BAQwFADBiMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
HwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMTMwODAxMTIwMDAwWhcNMzgwMTE1
MTIwMDAwWjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0G
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEp
pz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9o
k3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGY
QJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6
MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtm
mnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7
f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFH
dL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8
oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wDQYJKoZIhvcNAQEMBQAD
ggIBALth2X2pbL4XxJEbw6GiAI3jZGgPVs93rnD5/ZpKmbnJeFwMDF/k5hQpVgs2SV1EY+CtnJYY
ZhsjDT156W1r1lT40jzBQ0CuHVD1UvyQO7uYmWlrx8GnqGikJ9yd+SeuMIW59mdNOj6PWTkiU0Tr
yF0Dyu1Qen1iIQqAyHNm0aAFYF/opbSnr6j3bTWcfFqK1qI4mfN4i/RN0iAL3gTujJtHgXINwBQy
7zBZLq7gcfJW5GqXb5JQbZaNaHqasjYUegbyJLkJEVDXCLG4iXqEI2FCKeWjzaIgQdfRnGTZ6iah
ixTXTBmyUEFxPT9NcCOGDErcgdLMMpSEDQgJlxxPwO5rIHQw0uA5NBCFIRUBCOhVMt5xSdkoF1BN
5r5N0XWs0Mr7QbhDparTwwVETyw2m+L64kW4I1NsBm9nVX9GtUw/bihaeSbSpKhil9Ie4u1Ki7wb
/UdKDd9nZn6yW0HQO+T0O/QEY+nvwlQAUaCKKsnOeMzV6ocEGLPOr0mIr/OSmbaz5mEP0oUA51Aa
5BuVnRmhuZyxm7EAHu/QD09CbMkKvO5D+jpxpchNJqU1/YldvIViHTLSoCtU7ZpXwdv6EM8Zt4tK
G48BtieVU+i2iW1bvGjUI+iLUaJW+fCmgKDWHrO8Dw9TdSmq6hN35N6MgSGtBxBHEa2HPQfRdbzP
82Z+
-----END CERTIFICATE-----

COMODO RSA Certification Authority
==================================
-----BEGIN CERTIFICATE-----
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
LaZRfyHBNVOFBkpdn627G190
-----END CERTIFICATE-----

USERTrust RSA Certification Authority
=====================================
-----BEGIN CERTIFICATE-----
MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UE
BhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQK
ExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwHhcNMTAwMjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UE
BhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQK
ExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCAEmUXNg7D2wiz
0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2j
Y0K2dvKpOyuR+OJv0OwWIJAJPuLodMkYtJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFn
RghRy4YUVD+8M/5+bJz/Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O
+T23LLb2VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT79uq
/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6c0Plfg6lZrEpfDKE
Y1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmTYo61Zs8liM2EuLE/pDkP2QKe6xJM
lXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97lc6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8
yexDJtC/QV9AqURE9JnnV4eeUB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+
eLf8ZxXhyVeEHg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd
BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPFUp/L+M+ZBn8b2kMVn54CVVeW
FPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KOVWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ
7l8wXEskEVX/JJpuXior7gtNn3/3ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQ
Eg9zKC7F4iRO/Fjs8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM
8WcRiQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYzeSf7dNXGi
FSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZXHlKYC6SQK5MNyosycdi
yA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9c
J2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRBVXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGw
sAvgnEzDHNb842m1R0aBL6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gx
Q+6IHdfGjjxDah2nGN59PRbxYvnKkKj9
-----END CERTIFICATE-----

USERTrust ECC Certification Authority
=====================================
-----BEGIN CERTIFICATE-----
MIICjzCCAhWgAwIBAgIQXIuZxVqUxdJxVt7NiYDMJjAKBggqhkjOPQQDAzCBiDELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkwHhcNMTAwMjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQarFRaqfloI+d61SRvU8Za2EurxtW2
0eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinngo4N+LZfQYcTxmdwlkWOrfzCjtHDix6Ez
nPO/LlxTsV+zfTJ/ijTjeXmjQjBAMB0GA1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAOBgNV
HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjA2Z6EWCNzklwBB
HU6+4WMBzzuqQhFkoJ2UOQIReVx7Hfpkue4WQrO/isIJxOzksU0CMQDpKmFHjFJKS04YcPbWRNZu
9YO6bVi9JNlWSOrvxKJGgYhqOkbRqZtNyWHa0V1Xahg=
-----END CERTIFICATE-----

GlobalSign ECC Root CA - R4
===========================
-----BEGIN CERTIFICATE-----
MIIB4TCCAYegAwIBAgIRKjikHJYKBN5CsiilC+g0mAIwCgYIKoZIzj0EAwIwUDEkMCIGA1UECxMb
R2xvYmFsU2lnbiBFQ0MgUm9vdCBDQSAtIFI0MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQD
EwpHbG9iYWxTaWduMB4XDTEyMTExMzAwMDAwMFoXDTM4MDExOTAzMTQwN1owUDEkMCIGA1UECxMb
R2xvYmFsU2lnbiBFQ0MgUm9vdCBDQSAtIFI0MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQD
EwpHbG9iYWxTaWduMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuMZ5049sJQ6fLjkZHAOkrprl
OQcJFspjsbmG+IpXwVfOQvpzofdlQv8ewQCybnMO/8ch5RikqtlxP6jUuc6MHaNCMEAwDgYDVR0P
AQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFFSwe61FuOJAf/sKbvu+M8k8o4TV
MAoGCCqGSM49BAMCA0gAMEUCIQDckqGgE6bPA7DmxCGXkPoUVy0D7O48027KqGx2vKLeuwIgJ6iF
JzWbVsaj8kfSt24bAgAXqmemFZHe+pTsewv4n4Q=
-----END CERTIFICATE-----

GlobalSign ECC Root CA - R5
===========================
-----BEGIN CERTIFICATE-----
MIICHjCCAaSgAwIBAgIRYFlJ4CYuu1X5CneKcflK2GwwCgYIKoZIzj0EAwMwUDEkMCIGA1UECxMb
R2xvYmFsU2lnbiBFQ0MgUm9vdCBDQSAtIFI1MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQD
EwpHbG9iYWxTaWduMB4XDTEyMTExMzAwMDAwMFoXDTM4MDExOTAzMTQwN1owUDEkMCIGA1UECxMb
R2xvYmFsU2lnbiBFQ0MgUm9vdCBDQSAtIFI1MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQD
EwpHbG9iYWxTaWduMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAER0UOlvt9Xb/pOdEh+J8LttV7HpI6
SFkc8GIxLcB6KP4ap1yztsyX50XUWPrRd21DosCHZTQKH3rd6zwzocWdTaRvQZU4f8kehOvRnkmS
h5SHDDqFSmafnVmTTZdhBoZKo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUPeYpSJvqB8ohREom3m7e0oPQn1kwCgYIKoZIzj0EAwMDaAAwZQIxAOVpEslu28Yx
uglB4Zf4+/2a4n0Sye18ZNPLBSWLVtmg515dTguDnFt2KaAJJiFqYgIwcdK1j1zqO+F4CYWodZI7
yFz9SO8NdCKoCOJuxUnOxwy8p2Fp8fc74SrL+SvzZpA3
-----END CERTIFICATE-----

Staat der Nederlanden Root CA - G3
==================================
-----BEGIN CERTIFICATE-----
MIIFdDCCA1ygAwIBAgIEAJiiOTANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJOTDEeMBwGA1UE
CgwVU3RhYXQgZGVyIE5lZGVybGFuZGVuMSswKQYDVQQDDCJTdGFhdCBkZXIgTmVkZXJsYW5kZW4g
Um9vdCBDQSAtIEczMB4XDTEzMTExNDExMjg0MloXDTI4MTExMzIzMDAwMFowWjELMAkGA1UEBhMC
TkwxHjAcBgNVBAoMFVN0YWF0IGRlciBOZWRlcmxhbmRlbjErMCkGA1UEAwwiU3RhYXQgZGVyIE5l
ZGVybGFuZGVuIFJvb3QgQ0EgLSBHMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL4y
olQPcPssXFnrbMSkUeiFKrPMSjTysF/zDsccPVMeiAho2G89rcKezIJnByeHaHE6n3WWIkYFsO2t
x1ueKt6c/DrGlaf1F2cY5y9JCAxcz+bMNO14+1Cx3Gsy8KL+tjzk7FqXxz8ecAgwoNzFs21v0IJy
EavSgWhZghe3eJJg+szeP4TrjTgzkApyI/o1zCZxMdFyKJLZWyNtZrVtB0LrpjPOktvA9mxjeM3K
Tj215VKb8b475lRgsGYeCasH/lSJEULR9yS6YHgamPfJEf0WwTUaVHXvQ9Plrk7O53vDxk5hUUur
mkVLoR9BvUhTFXFkC4az5S6+zqQbwSmEorXLCCN2QyIkHxcE1G6cxvx/K2Ya7Irl1s9N9WMJtxU5
1nus6+N86U78dULI7ViVDAZCopz35HCz33JvWjdAidiFpNfxC95DGdRKWCyMijmev4SH8RY7Ngzp
07TKbBlBUgmhHbBqv4LvcFEhMtwFdozL92TkA1CvjJFnq8Xy7ljY3r735zHPbMk7ccHViLVlvMDo
FxcHErVc0qsgk7TmgoNwNsXNo42ti+yjwUOH5kPiNL6VizXtBznaqB16nzaeErAMZRKQFWDZJkBE
41ZgpRDUajz9QdwOWke275dhdU/Z/seyHdTtXUmzqWrLZoQT1Vyg3N9udwbRcXXIV2+vD3dbAgMB
AAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRUrfrHkleu
yjWcLhL75LpdINyUVzANBgkqhkiG9w0BAQsFAAOCAgEAMJmdBTLIXg47mAE6iqTnB/d6+Oea31BD
U5cqPco8R5gu4RV78ZLzYdqQJRZlwJ9UXQ4DO1t3ApyEtg2YXzTdO2PCwyiBwpwpLiniyMMB8jPq
KqrMCQj3ZWfGzd/TtiunvczRDnBfuCPRy5FOCvTIeuXZYzbB1N/8Ipf3YF3qKS9Ysr1YvY2WTxB1
v0h7PVGHoTx0IsL8B3+A3MSs/mrBcDCw6Y5p4ixpgZQJut3+TcCDjJRYwEYgr5wfAvg1VUkvRtTA
8KCWAg8zxXHzniN9lLf9OtMJgwYh/WA9rjLA0u6NpvDntIJ8CsxwyXmA+P5M9zWEGYox+wrZ13+b
8KKaa8MFSu1BYBQw0aoRQm7TIwIEC8Zl3d1Sd9qBa7Ko+gE4uZbqKmxnl4mUnrzhVNXkanjvSr0r
mj1AfsbAddJu+2gw7OyLnflJNZoaLNmzlTnVHpL3prllL+U9bTpITAjc5CgSKL59NVzq4BZ+Extq
1z7XnvwtdbLBFNUjA9tbbws+eC8N3jONFrdI54OagQ97wUNNVQQXOEpR1VmiiXTTn74eS9fGbbeI
JG9gkaSChVtWQbzQRKtqE77RLFi3EjNYsjdj3BP1lB0/QFH1T/U67cjF68IeHRaVesd+QnGTbksV
tzDfqu1XhUisHWrdOWnk4Xl4vs4Fv6EM94B7IWcnMFk=
-----END CERTIFICATE-----

Staat der Nederlanden EV Root CA
================================
-----BEGIN CERTIFICATE-----
MIIFcDCCA1igAwIBAgIEAJiWjTANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJOTDEeMBwGA1UE
CgwVU3RhYXQgZGVyIE5lZGVybGFuZGVuMSkwJwYDVQQDDCBTdGFhdCBkZXIgTmVkZXJsYW5kZW4g
RVYgUm9vdCBDQTAeFw0xMDEyMDgxMTE5MjlaFw0yMjEyMDgxMTEwMjhaMFgxCzAJBgNVBAYTAk5M
MR4wHAYDVQQKDBVTdGFhdCBkZXIgTmVkZXJsYW5kZW4xKTAnBgNVBAMMIFN0YWF0IGRlciBOZWRl
cmxhbmRlbiBFViBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA48d+ifkk
SzrSM4M1LGns3Amk41GoJSt5uAg94JG6hIXGhaTK5skuU6TJJB79VWZxXSzFYGgEt9nCUiY4iKTW
O0Cmws0/zZiTs1QUWJZV1VD+hq2kY39ch/aO5ieSZxeSAgMs3NZmdO3dZ//BYY1jTw+bbRcwJu+r
0h8QoPnFfxZpgQNH7R5ojXKhTbImxrpsX23Wr9GxE46prfNeaXUmGD5BKyF/7otdBwadQ8QpCiv8
Kj6GyzyDOvnJDdrFmeK8eEEzduG/L13lpJhQDBXd4Pqcfzho0LKmeqfRMb1+ilgnQ7O6M5HTp5gV
XJrm0w912fxBmJc+qiXbj5IusHsMX/FjqTf5m3VpTCgmJdrV8hJwRVXj33NeN/UhbJCONVrJ0yPr
08C+eKxCKFhmpUZtcALXEPlLVPxdhkqHz3/KRawRWrUgUY0viEeXOcDPusBCAUCZSCELa6fS/ZbV
0b5GnUngC6agIk440ME8MLxwjyx1zNDFjFE7PZQIZCZhfbnDZY8UnCHQqv0XcgOPvZuM5l5Tnrmd
74K74bzickFbIZTTRTeU0d8JOV3nI6qaHcptqAqGhYqCvkIH1vI4gnPah1vlPNOePqc7nvQDs/nx
fRN0Av+7oeX6AHkcpmZBiFxgV6YuCcS6/ZrPpx9Aw7vMWgpVSzs4dlG4Y4uElBbmVvMCAwEAAaNC
MEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFP6rAJCYniT8qcwa
ivsnuL8wbqg7MA0GCSqGSIb3DQEBCwUAA4ICAQDPdyxuVr5Os7aEAJSrR8kN0nbHhp8dB9O2tLsI
eK9p0gtJ3jPFrK3CiAJ9Brc1AsFgyb/E6JTe1NOpEyVa/m6irn0F3H3zbPB+po3u2dfOWBfoqSmu
c0iH55vKbimhZF8ZE/euBhD/UcabTVUlT5OZEAFTdfETzsemQUHSv4ilf0X8rLiltTMMgsT7B/Zq
5SWEXwbKwYY5EdtYzXc7LMJMD16a4/CrPmEbUCTCwPTxGfARKbalGAKb12NMcIxHowNDXLldRqAN
b/9Zjr7dn3LDWyvfjFvO5QxGbJKyCqNMVEIYFRIYvdr8unRu/8G2oGTYqV9Vrp9canaW2HNnh/tN
f1zuacpzEPuKqf2evTY4SUmH9A4U8OmHuD+nT3pajnnUk+S7aFKErGzp85hwVXIy+TSrK0m1zSBi
5Dp6Z2Orltxtrpfs/J92VoguZs9btsmksNcFuuEnL5O7Jiqik7Ab846+HUCjuTaPPoIaGl6I6lD4
WeKDRikL40Rc4ZW2aZCaFG+XroHPaO+Zmr615+F/+PoTRxZMzG0IQOeLeG9QgkRQP2YGiqtDhFZK
DyAthg710tvSeopLzaXoTvFeJiUBWSOgftL2fiFX1ye8FVdMpEbB4IMeDExNH08GGeL5qPQ6gqGy
eUN51q1veieQA6TqJIc/2b3Z6fJfUEkc7uzXLg==
-----END CERTIFICATE-----

IdenTrust Commercial Root CA 1
==============================
-----BEGIN CERTIFICATE-----
MIIFYDCCA0igAwIBAgIQCgFCgAAAAUUjyES1AAAAAjANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQG
EwJVUzESMBAGA1UEChMJSWRlblRydXN0MScwJQYDVQQDEx5JZGVuVHJ1c3QgQ29tbWVyY2lhbCBS
b290IENBIDEwHhcNMTQwMTE2MTgxMjIzWhcNMzQwMTE2MTgxMjIzWjBKMQswCQYDVQQGEwJVUzES
MBAGA1UEChMJSWRlblRydXN0MScwJQYDVQQDEx5JZGVuVHJ1c3QgQ29tbWVyY2lhbCBSb290IENB
IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCnUBneP5k91DNG8W9RYYKyqU+PZ4ld
hNlT3Qwo2dfw/66VQ3KZ+bVdfIrBQuExUHTRgQ18zZshq0PirK1ehm7zCYofWjK9ouuU+ehcCuz/
mNKvcbO0U59Oh++SvL3sTzIwiEsXXlfEU8L2ApeN2WIrvyQfYo3fw7gpS0l4PJNgiCL8mdo2yMKi
1CxUAGc1bnO/AljwpN3lsKImesrgNqUZFvX9t++uP0D1bVoE/c40yiTcdCMbXTMTEl3EASX2MN0C
XZ/g1Ue9tOsbobtJSdifWwLziuQkkORiT0/Br4sOdBeo0XKIanoBScy0RnnGF7HamB4HWfp1IYVl
3ZBWzvurpWCdxJ35UrCLvYf5jysjCiN2O/cz4ckA82n5S6LgTrx+kzmEB/dEcH7+B1rlsazRGMzy
NeVJSQjKVsk9+w8YfYs7wRPCTY/JTw436R+hDmrfYi7LNQZReSzIJTj0+kuniVyc0uMNOYZKdHzV
WYfCP04MXFL0PfdSgvHqo6z9STQaKPNBiDoT7uje/5kdX7rL6B7yuVBgwDHTc+XvvqDtMwt0viAg
xGds8AgDelWAf0ZOlqf0Hj7h9tgJ4TNkK2PXMl6f+cB7D3hvl7yTmvmcEpB4eoCHFddydJxVdHix
uuFucAS6T6C6aMN7/zHwcz09lCqxC0EOoP5NiGVreTO01wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7UQZwNPwBovupHu+QucmVMiONnYwDQYJKoZI
hvcNAQELBQADggIBAA2ukDL2pkt8RHYZYR4nKM1eVO8lvOMIkPkp165oCOGUAFjvLi5+U1KMtlwH
6oi6mYtQlNeCgN9hCQCTrQ0U5s7B8jeUeLBfnLOic7iPBZM4zY0+sLj7wM+x8uwtLRvM7Kqas6pg
ghstO8OEPVeKlh6cdbjTMM1gCIOQ045U8U1mwF10A0Cj7oV+wh93nAbowacYXVKV7cndJZ5t+qnt
ozo00Fl72u1Q8zW/7esUTTHHYPTa8Yec4kjixsU3+wYQ+nVZZjFHKdp2mhzpgq7vmrlR94gjmmmV
YjzlVYA211QC//G5Xc7UI2/YRYRKW2XviQzdFKcgyxilJbQN+QHwotL0AMh0jqEqSI5l2xPE4iUX
feu+h1sXIFRRk0pTAwvsXcoz7WL9RccvW9xYoIA55vrX/hMUpu09lEpCdNTDd1lzzY9GvlU47/ro
kTLql1gEIt44w8y8bckzOmoKaT+gyOpyj4xjhiO9bTyWnpXgSUyqorkqG5w2gXjtw+hG4iZZRHUe
2XWJUc0QhJ1hYMtd+ZciTY6Y5uN/9lu7rs3KSoFrXgvzUeF0K+l+J6fZmUlO+KWA2yUPHGNiiskz
Z2s8EIPGrd6ozRaOjfAHN3Gf8qv8QfXBi+wAN10J5U6A7/qxXDgGpRtK4dw4LTzcqx+QGtVKnO7R
cGzM7vRX+Bi6hG6H
-----END CERTIFICATE-----

IdenTrust Public Sector Root CA 1
=================================
-----BEGIN CERTIFICATE-----
MIIFZjCCA06gAwIBAgIQCgFCgAAAAUUjz0Z8AAAAAjANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQG
EwJVUzESMBAGA1UEChMJSWRlblRydXN0MSowKAYDVQQDEyFJZGVuVHJ1c3QgUHVibGljIFNlY3Rv
ciBSb290IENBIDEwHhcNMTQwMTE2MTc1MzMyWhcNMzQwMTE2MTc1MzMyWjBNMQswCQYDVQQGEwJV
UzESMBAGA1UEChMJSWRlblRydXN0MSowKAYDVQQDEyFJZGVuVHJ1c3QgUHVibGljIFNlY3RvciBS
b290IENBIDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2IpT8pEiv6EdrCvsnduTy
P4o7ekosMSqMjbCpwzFrqHd2hCa2rIFCDQjrVVi7evi8ZX3yoG2LqEfpYnYeEe4IFNGyRBb06tD6
Hi9e28tzQa68ALBKK0CyrOE7S8ItneShm+waOh7wCLPQ5CQ1B5+ctMlSbdsHyo+1W/CD80/HLaXI
rcuVIKQxKFdYWuSNG5qrng0M8gozOSI5Cpcu81N3uURF/YTLNiCBWS2ab21ISGHKTN9T0a9SvESf
qy9rg3LvdYDaBjMbXcjaY8ZNzaxmMc3R3j6HEDbhuaR672BQssvKplbgN6+rNBM5Jeg5ZuSYeqoS
mJxZZoY+rfGwyj4GD3vwEUs3oERte8uojHH01bWRNszwFcYr3lEXsZdMUD2xlVl8BX0tIdUAvwFn
ol57plzy9yLxkA2T26pEUWbMfXYD62qoKjgZl3YNa4ph+bz27nb9cCvdKTz4Ch5bQhyLVi9VGxyh
LrXHFub4qjySjmm2AcG1hp2JDws4lFTo6tyePSW8Uybt1as5qsVATFSrsrTZ2fjXctscvG29ZV/v
iDUqZi/u9rNl8DONfJhBaUYPQxxp+pu10GFqzcpL2UyQRqsVWaFHVCkugyhfHMKiq3IXAAaOReyL
4jM9f9oZRORicsPfIsbyVtTdX5Vy7W1f90gDW/3FKqD2cyOEEBsB5wIDAQABo0IwQDAOBgNVHQ8B
Af8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU43HgntinQtnbcZFrlJPrw6PRFKMw
DQYJKoZIhvcNAQELBQADggIBAEf63QqwEZE4rU1d9+UOl1QZgkiHVIyqZJnYWv6IAcVYpZmxI1Qj
t2odIFflAWJBF9MJ23XLblSQdf4an4EKwt3X9wnQW3IV5B4Jaj0z8yGa5hV+rVHVDRDtfULAj+7A
mgjVQdZcDiFpboBhDhXAuM/FSRJSzL46zNQuOAXeNf0fb7iAaJg9TaDKQGXSc3z1i9kKlT/YPyNt
GtEqJBnZhbMX73huqVjRI9PHE+1yJX9dsXNw0H8GlwmEKYBhHfpe/3OsoOOJuBxxFcbeMX8S3OFt
m6/n6J91eEyrRjuazr8FGF1NFTwWmhlQBJqymm9li1JfPFgEKCXAZmExfrngdbkaqIHWchezxQMx
NRF4eKLg6TCMf4DfWN88uieW4oA0beOY02QnrEh+KHdcxiVhJfiFDGX6xDIvpZgF5PgLZxYWxoK4
Mhn5+bl53B/N66+rDt0b20XkeucC4pVd/GnwU2lhlXV5C15V5jgclKlZM57IcXR5f1GJtshquDDI
ajjDbp7hNxbqBWJMWxJH7ae0s1hWx0nzfxJoCTFx8G34Tkf71oXuxVhAGaQdp/lLQzfcaFpPz+vC
ZHTetBXZ9FRUGi8c15dxVJCO2SCdUyt/q4/i6jC8UDfv8Ue1fXwsBOxonbRJRBD0ckscZOf85muQ
3Wl9af0AVqW3rLatt8o+Ae+c
-----END CERTIFICATE-----

Entrust Root Certification Authority - G2
=========================================
-----BEGIN CERTIFICATE-----
MIIEPjCCAyagAwIBAgIESlOMKDANBgkqhkiG9w0BAQsFADCBvjELMAkGA1UEBhMCVVMxFjAUBgNV
BAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVy
bXMxOTA3BgNVBAsTMChjKSAyMDA5IEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ug
b25seTEyMDAGA1UEAxMpRW50cnVzdCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzIw
HhcNMDkwNzA3MTcyNTU0WhcNMzAxMjA3MTc1NTU0WjCBvjELMAkGA1UEBhMCVVMxFjAUBgNVBAoT
DUVudHJ1c3QsIEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMx
OTA3BgNVBAsTMChjKSAyMDA5IEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25s
eTEyMDAGA1UEAxMpRW50cnVzdCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6hLZy254Ma+KZ6TABp3bqMriVQRrJ2mFOWHLP
/vaCeb9zYQYKpSfYs1/TRU4cctZOMvJyig/3gxnQaoCAAEUesMfnmr8SVycco2gvCoe9amsOXmXz
HHfV1IWNcCG0szLni6LVhjkCsbjSR87kyUnEO6fe+1R9V77w6G7CebI6C1XiUJgWMhNcL3hWwcKU
s/Ja5CeanyTXxuzQmyWC48zCxEXFjJd6BmsqEZ+pCm5IO2/b1BEZQvePB7/1U1+cPvQXLOZprE4y
TGJ36rfo5bs0vBmLrpxR57d+tVOxMyLlbc9wPBr64ptntoP0jaWvYkxN4FisZDQSA/i2jZRjJKRx
AgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRqciZ6
0B7vfec7aVHUbI2fkBJmqzANBgkqhkiG9w0BAQsFAAOCAQEAeZ8dlsa2eT8ijYfThwMEYGprmi5Z
iXMRrEPR9RP/jTkrwPK9T3CMqS/qF8QLVJ7UG5aYMzyorWKiAHarWWluBh1+xLlEjZivEtRh2woZ
Rkfz6/djwUAFQKXSt/S1mja/qYh2iARVBCuch38aNzx+LaUa2NSJXsq9rD1s2G2v1fN2D807iDgi
nWyTmsQ9v4IbZT+mD12q/OWyFcq1rca8PdCE6OoGcrBNOTJ4vz4RnAuknZoh8/CbCzB428Hch0P+
vGOaysXCHMnHjf87ElgI5rY97HosTvuDls4MPGmHVHOkc8KT/1EQrBVUAdj8BbGJoX90g5pJ19xO
e4pIb4tF9g==
-----END CERTIFICATE-----

Entrust Root Certification Authority - EC1
==========================================
-----BEGIN CERTIFICATE-----
MIIC+TCCAoCgAwIBAgINAKaLeSkAAAAAUNCR+TAKBggqhkjOPQQDAzCBvzELMAkGA1UEBhMCVVMx
FjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVn
YWwtdGVybXMxOTA3BgNVBAsTMChjKSAyMDEyIEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXpl
ZCB1c2Ugb25seTEzMDEGA1UEAxMqRW50cnVzdCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5
IC0gRUMxMB4XDTEyMTIxODE1MjUzNloXDTM3MTIxODE1NTUzNlowgb8xCzAJBgNVBAYTAlVTMRYw
FAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQLEx9TZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2Fs
LXRlcm1zMTkwNwYDVQQLEzAoYykgMjAxMiBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQg
dXNlIG9ubHkxMzAxBgNVBAMTKkVudHJ1c3QgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAt
IEVDMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIQTydC6bUF74mzQ61VfZgIaJPRbiWlH47jCffHy
AsWfoPZb1YsGGYZPUxBtByQnoaD41UcZYUx9ypMn6nQM72+WCf5j7HBdNq1nd67JnXxVRDqiY1Ef
9eNi1KlHBz7MIKNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
FLdj5xrdjekIplWDpOBqUEFlEUJJMAoGCCqGSM49BAMDA2cAMGQCMGF52OVCR98crlOZF7ZvHH3h
vxGU0QOIdeSNiaSKd0bebWHvAvX7td/M/k7//qnmpwIwW5nXhTcGtXsI/esni0qU+eH6p44mCOh8
kmhtc9hvJqwhAriZtyZBWyVgrtBIGu4G
-----END CERTIFICATE-----

CFCA EV ROOT
============
-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIEGErM1jANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJDTjEwMC4GA1UE
CgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYDVQQDDAxDRkNB
IEVWIFJPT1QwHhcNMTIwODA4MDMwNzAxWhcNMjkxMjMxMDMwNzAxWjBWMQswCQYDVQQGEwJDTjEw
MC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRUwEwYDVQQD
DAxDRkNBIEVWIFJPT1QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDXXWvNED8fBVnV
BU03sQ7smCuOFR36k0sXgiFxEFLXUWRwFsJVaU2OFW2fvwwbwuCjZ9YMrM8irq93VCpLTIpTUnrD
7i7es3ElweldPe6hL6P3KjzJIx1qqx2hp/Hz7KDVRM8Vz3IvHWOX6Jn5/ZOkVIBMUtRSqy5J35DN
uF++P96hyk0g1CXohClTt7GIH//62pCfCqktQT+x8Rgp7hZZLDRJGqgG16iI0gNyejLi6mhNbiyW
ZXvKWfry4t3uMCz7zEasxGPrb382KzRzEpR/38wmnvFyXVBlWY9ps4deMm/DGIq1lY+wejfeWkU7
xzbh72fROdOXW3NiGUgthxwG+3SYIElz8AXSG7Ggo7cbcNOIabla1jj0Ytwli3i/+Oh+uFzJlU9f
py25IGvPa931DfSCt/SyZi4QKPaXWnuWFo8BGS1sbn85WAZkgwGDg8NNkt0yxoekN+kWzqotaK8K
gWU6cMGbrU1tVMoqLUuFG7OA5nBFDWteNfB/O7ic5ARwiRIlk9oKmSJgamNgTnYGmE69g60dWIol
hdLHZR4tjsbftsbhf4oEIRUpdPA+nJCdDC7xij5aqgwJHsfVPKPtl8MeNPo4+QgO48BdK4PRVmrJ
tqhUUy54Mmc9gn900PvhtgVguXDbjgv5E1hvcWAQUhC5wUEJ73IfZzF4/5YFjQIDAQABo2MwYTAf
BgNVHSMEGDAWgBTj/i39KNALtbq2osS/BqoFjJP7LzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIBBjAdBgNVHQ4EFgQU4/4t/SjQC7W6tqLEvwaqBYyT+y8wDQYJKoZIhvcNAQELBQADggIB
ACXGumvrh8vegjmWPfBEp2uEcwPenStPuiB/vHiyz5ewG5zz13ku9Ui20vsXiObTej/tUxPQ4i9q
ecsAIyjmHjdXNYmEwnZPNDatZ8POQQaIxffu2Bq41gt/UP+TqhdLjOztUmCypAbqTuv0axn96/Ua
4CUqmtzHQTb3yHQFhDmVOdYLO6Qn+gjYXB74BGBSESgoA//vU2YApUo0FmZ8/Qmkrp5nGm9BC2sG
E5uPhnEFtC+NiWYzKXZUmhH4J/qyP5Hgzg0b8zAarb8iXRvTvyUFTeGSGn+ZnzxEk8rUQElsgIfX
BDrDMlI1Dlb4pd19xIsNER9Tyx6yF7Zod1rg1MvIB671Oi6ON7fQAUtDKXeMOZePglr4UeWJoBjn
aH9dCi77o0cOPaYjesYBx4/IXr9tgFa+iiS6M+qf4TIRnvHST4D2G0CvOJ4RUHlzEhLN5mydLIhy
PDCBBpEi6lmt2hkuIsKNuYyH4Ga8cyNfIWRjgEj1oDwYPZTISEEdQLpe/v5WOaHIz16eGWRGENoX
kbcFgKyLmZJ956LYBws2J+dIeWCKw9cTXPhyQN9Ky8+ZAAoACxGV2lZFA4gKn2fQ1XmxqI1AbQ3C
ekD6819kR5LLU7m7Wc5P/dAVUwHY3+vZ5nbv0CO7O6l5s9UCKc2Jo5YPSjXnTkLAdc0Hz+Ys63su
-----END CERTIFICATE-----

OISTE WISeKey Global Root GB CA
===============================
-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIQdrEgUnTwhYdGs/gjGvbCwDANBgkqhkiG9w0BAQsFADBtMQswCQYDVQQG
EwJDSDEQMA4GA1UEChMHV0lTZUtleTEiMCAGA1UECxMZT0lTVEUgRm91bmRhdGlvbiBFbmRvcnNl
ZDEoMCYGA1UEAxMfT0lTVEUgV0lTZUtleSBHbG9iYWwgUm9vdCBHQiBDQTAeFw0xNDEyMDExNTAw
MzJaFw0zOTEyMDExNTEwMzFaMG0xCzAJBgNVBAYTAkNIMRAwDgYDVQQKEwdXSVNlS2V5MSIwIAYD
VQQLExlPSVNURSBGb3VuZGF0aW9uIEVuZG9yc2VkMSgwJgYDVQQDEx9PSVNURSBXSVNlS2V5IEds
b2JhbCBSb290IEdCIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Be3HEokKtaX
scriHvt9OO+Y9bI5mE4nuBFde9IllIiCFSZqGzG7qFshISvYD06fWvGxWuR51jIjK+FTzJlFXHtP
rby/h0oLS5daqPZI7H17Dc0hBt+eFf1Biki3IPShehtX1F1Q/7pn2COZH8g/497/b1t3sWtuuMlk
9+HKQUYOKXHQuSP8yYFfTvdv37+ErXNku7dCjmn21HYdfp2nuFeKUWdy19SouJVUQHMD9ur06/4o
Qnc/nSMbsrY9gBQHTC5P99UKFg29ZkM3fiNDecNAhvVMKdqOmq0NpQSHiB6F4+lT1ZvIiwNjeOvg
GUpuuy9rM2RYk61pv48b74JIxwIDAQABo1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
/zAdBgNVHQ4EFgQUNQ/INmNe4qPs+TtmFc5RUuORmj0wEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZI
hvcNAQELBQADggEBAEBM+4eymYGQfp3FsLAmzYh7KzKNbrghcViXfa43FK8+5/ea4n32cZiZBKpD
dHij40lhPnOMTZTg+XHEthYOU3gf1qKHLwI5gSk8rxWYITD+KJAAjNHhy/peyP34EEY7onhCkRd0
VQreUGdNZtGn//3ZwLWoo4rOZvUPQ82nK1d7Y0Zqqi5S2PTt4W2tKZB4SLrhI6qjiey1q5bAtEui
HZeeevJuQHHfaPFlTc58Bd9TZaml8LGXBHAVRgOY1NK/VLSgWH1Sb9pWJmLU2NuJMW8c8CLC02Ic
Nc1MaRVUGpCY3useX8p3x8uOPUNpnJpY0CQ73xtAln41rYHHTnG6iBM=
-----END CERTIFICATE-----

SZAFIR ROOT CA2
===============
-----BEGIN CERTIFICATE-----
MIIDcjCCAlqgAwIBAgIUPopdB+xV0jLVt+O2XwHrLdzk1uQwDQYJKoZIhvcNAQELBQAwUTELMAkG
A1UEBhMCUEwxKDAmBgNVBAoMH0tyYWpvd2EgSXpiYSBSb3psaWN6ZW5pb3dhIFMuQS4xGDAWBgNV
BAMMD1NaQUZJUiBST09UIENBMjAeFw0xNTEwMTkwNzQzMzBaFw0zNTEwMTkwNzQzMzBaMFExCzAJ
BgNVBAYTAlBMMSgwJgYDVQQKDB9LcmFqb3dhIEl6YmEgUm96bGljemVuaW93YSBTLkEuMRgwFgYD
VQQDDA9TWkFGSVIgUk9PVCBDQTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3vD5Q
qEvNQLXOYeeWyrSh2gwisPq1e3YAd4wLz32ohswmUeQgPYUM1ljj5/QqGJ3a0a4m7utT3PSQ1hNK
DJA8w/Ta0o4NkjrcsbH/ON7Dui1fgLkCvUqdGw+0w8LBZwPd3BucPbOw3gAeqDRHu5rr/gsUvTaE
2g0gv/pby6kWIK05YO4vdbbnl5z5Pv1+TW9NL++IDWr63fE9biCloBK0TXC5ztdyO4mTp4CEHCdJ
ckm1/zuVnsHMyAHs6A6KCpbns6aH5db5BSsNl0BwPLqsdVqc1U2dAgrSS5tmS0YHF2Wtn2yIANwi
ieDhZNRnvDF5YTy7ykHNXGoAyDw4jlivAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgEGMB0GA1UdDgQWBBQuFqlKGLXLzPVvUPMjX/hd56zwyDANBgkqhkiG9w0BAQsFAAOC
AQEAtXP4A9xZWx126aMqe5Aosk3AM0+qmrHUuOQn/6mWmc5G4G18TKI4pAZw8PRBEew/R40/cof5
O/2kbytTAOD/OblqBw7rHRz2onKQy4I9EYKL0rufKq8h5mOGnXkZ7/e7DDWQw4rtTw/1zBLZpD67
oPwglV9PJi8RI4NOdQcPv5vRtB3pEAT+ymCPoky4rc/hkA/NrgrHXXu3UNLUYfrVFdvXn4dRVOul
4+vJhaAlIDf7js4MNIThPIGyd05DpYhfhmehPea0XGG2Ptv+tyjFogeutcrKjSoS75ftwjCkySp6
+/NNIxuZMzSgLvWpCz/UXeHPhJ/iGcJfitYgHuNztw==
-----END CERTIFICATE-----

Certum Trusted Network CA 2
===========================
-----BEGIN CERTIFICATE-----
MIIF0jCCA7qgAwIBAgIQIdbQSk8lD8kyN/yqXhKN6TANBgkqhkiG9w0BAQ0FADCBgDELMAkGA1UE
BhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAlBgNVBAsTHkNlcnR1
bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMbQ2VydHVtIFRydXN0ZWQgTmV0d29y
ayBDQSAyMCIYDzIwMTExMDA2MDgzOTU2WhgPMjA0NjEwMDYwODM5NTZaMIGAMQswCQYDVQQGEwJQ
TDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dpZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENl
cnRpZmljYXRpb24gQXV0aG9yaXR5MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENB
IDIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC9+Xj45tWADGSdhhuWZGc/IjoedQF9
7/tcZ4zJzFxrqZHmuULlIEub2pt7uZld2ZuAS9eEQCsn0+i6MLs+CRqnSZXvK0AkwpfHp+6bJe+o
CgCXhVqqndwpyeI1B+twTUrWwbNWuKFBOJvR+zF/j+Bf4bE/D44WSWDXBo0Y+aomEKsq09DRZ40b
Rr5HMNUuctHFY9rnY3lEfktjJImGLjQ/KUxSiyqnwOKRKIm5wFv5HdnnJ63/mgKXwcZQkpsCLL2p
uTRZCr+ESv/f/rOf69me4Jgj7KZrdxYq28ytOxykh9xGc14ZYmhFV+SQgkK7QtbwYeDBoz1mo130
GO6IyY0XRSmZMnUCMe4pJshrAua1YkV/NxVaI2iJ1D7eTiew8EAMvE0Xy02isx7QBlrd9pPPV3WZ
9fqGGmd4s7+W/jTcvedSVuWz5XV710GRBdxdaeOVDUO5/IOWOZV7bIBaTxNyxtd9KXpEulKkKtVB
Rgkg/iKgtlswjbyJDNXXcPiHUv3a76xRLgezTv7QCdpw75j6VuZt27VXS9zlLCUVyJ4ueE742pye
hizKV/Ma5ciSixqClnrDvFASadgOWkaLOusm+iPJtrCBvkIApPjW/jAux9JG9uWOdf3yzLnQh1vM
BhBgu4M1t15n3kfsmUjxpKEV/q2MYo45VU85FrmxY53/twIDAQABo0IwQDAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBS2oVQ5AsOgP46KvPrU+Bym0ToO/TAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZI
hvcNAQENBQADggIBAHGlDs7k6b8/ONWJWsQCYftMxRQXLYtPU2sQF/xlhMcQSZDe28cmk4gmb3DW
Al45oPePq5a1pRNcgRRtDoGCERuKTsZPpd1iHkTfCVn0W3cLN+mLIMb4Ck4uWBzrM9DPhmDJ2vuA
L55MYIR4PSFk1vtBHxgP58l1cb29XN40hz5BsA72udY/CROWFC/emh1auVbONTqwX3BNXuMp8SMo
clm2q8KMZiYcdywmdjWLKKdpoPk79SPdhRB0yZADVpHnr7pH1BKXESLjokmUbOe3lEu6LaTaM4tM
pkT/WjzGHWTYtTHkpjx6qFcL2+1hGsvxznN3Y6SHb0xRONbkX8eftoEq5IVIeVheO/jbAoJnwTnb
w3RLPTYe+SmTiGhbqEQZIfCn6IENLOiTNrQ3ssqwGyZ6miUfmpqAnksqP/ujmv5zMnHCnsZy4Ypo
J/HkD7TETKVhk/iXEAcqMCWpuchxuO9ozC1+9eB+D4Kob7a6bINDd82Kkhehnlt4Fj1F4jNy3eFm
ypnTycUm/Q1oBEauttmbjL4ZvrHG8hnjXALKLNhvSgfZyTXaQHXyxKcZb55CEJh15pWLYLztxRLX
is7VmFxWlgPF7ncGNf/P5O4/E2Hu29othfDNrp2yGAlFw5Khchf8R7agCyzxxN5DaAhqXzvwdmP7
zAYspsbiDrW5viSP
-----END CERTIFICATE-----

Hellenic Academic and Research Institutions RootCA 2015
=======================================================
-----BEGIN CERTIFICATE-----
MIIGCzCCA/OgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBpjELMAkGA1UEBhMCR1IxDzANBgNVBAcT
BkF0aGVuczFEMEIGA1UEChM7SGVsbGVuaWMgQWNhZGVtaWMgYW5kIFJlc2VhcmNoIEluc3RpdHV0
aW9ucyBDZXJ0LiBBdXRob3JpdHkxQDA+BgNVBAMTN0hlbGxlbmljIEFjYWRlbWljIGFuZCBSZXNl
YXJjaCBJbnN0aXR1dGlvbnMgUm9vdENBIDIwMTUwHhcNMTUwNzA3MTAxMTIxWhcNNDAwNjMwMTAx
MTIxWjCBpjELMAkGA1UEBhMCR1IxDzANBgNVBAcTBkF0aGVuczFEMEIGA1UEChM7SGVsbGVuaWMg
QWNhZGVtaWMgYW5kIFJlc2VhcmNoIEluc3RpdHV0aW9ucyBDZXJ0LiBBdXRob3JpdHkxQDA+BgNV
BAMTN0hlbGxlbmljIEFjYWRlbWljIGFuZCBSZXNlYXJjaCBJbnN0aXR1dGlvbnMgUm9vdENBIDIw
MTUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDC+Kk/G4n8PDwEXT2QNrCROnk8Zlrv
bTkBSRq0t89/TSNTt5AA4xMqKKYx8ZEA4yjsriFBzh/a/X0SWwGDD7mwX5nh8hKDgE0GPt+sr+eh
iGsxr/CL0BgzuNtFajT0AoAkKAoCFZVedioNmToUW/bLy1O8E00BiDeUJRtCvCLYjqOWXjrZMts+
6PAQZe104S+nfK8nNLspfZu2zwnI5dMK/IhlZXQK3HMcXM1AsRzUtoSMTFDPaI6oWa7CJ06CojXd
FPQf/7J31Ycvqm59JCfnxssm5uX+Zwdj2EUN3TpZZTlYepKZcj2chF6IIbjV9Cz82XBST3i4vTwr
i5WY9bPRaM8gFH5MXF/ni+X1NYEZN9cRCLdmvtNKzoNXADrDgfgXy5I2XdGj2HUb4Ysn6npIQf1F
GQatJ5lOwXBH3bWfgVMS5bGMSF0xQxfjjMZ6Y5ZLKTBOhE5iGV48zpeQpX8B653g+IuJ3SWYPZK2
fu/Z8VFRfS0myGlZYeCsargqNhEEelC9MoS+L9xy1dcdFkfkR2YgP/SWxa+OAXqlD3pk9Q0Yh9mu
iNX6hME6wGkoLfINaFGq46V3xqSQDqE3izEjR8EJCOtu93ib14L8hCCZSRm2Ekax+0VVFqmjZayc
Bw/qa9wfLgZy7IaIEuQt218FL+TwA9MmM+eAws1CoRc0CwIDAQABo0IwQDAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUcRVnyMjJvXVdctA4GGqd83EkVAswDQYJKoZI
hvcNAQELBQADggIBAHW7bVRLqhBYRjTyYtcWNl0IXtVsyIe9tC5G8jH4fOpCtZMWVdyhDBKg2mF+
D1hYc2Ryx+hFjtyp8iY/xnmMsVMIM4GwVhO+5lFc2JsKT0ucVlMC6U/2DWDqTUJV6HwbISHTGzrM
d/K4kPFox/la/vot9L/J9UUbzjgQKjeKeaO04wlshYaT/4mWJ3iBj2fjRnRUjtkNaeJK9E10A/+y
d+2VZ5fkscWrv2oj6NSU4kQoYsRL4vDY4ilrGnB+JGGTe08DMiUNRSQrlrRGar9KC/eaj8GsGsVn
82800vpzY4zvFrCopEYq+OsS7HK07/grfoxSwIuEVPkvPuNVqNxmsdnhX9izjFk0WaSrT2y7Hxjb
davYy5LNlDhhDgcGH0tGEPEVvo2FXDtKK4F5D7Rpn0lQl033DlZdwJVqwjbDG2jJ9SrcR5q+ss7F
Jej6A7na+RZukYT1HCjI/CbM1xyQVqdfbzoEvM14iQuODy+jqk+iGxI9FghAD/FGTNeqewjBCvVt
J94Cj8rDtSvK6evIIVM4pcw72Hc3MKJP2W/R8kCtQXoXxdZKNYm3QdV8hn9VTYNKpXMgwDqvkPGa
JI7ZjnHKe7iG2rKPmT4dEw0SEe7Uq/DpFXYC5ODfqiAeW2GFZECpkJcNrVPSWh2HagCXZWK0vm9q
p/UsQu0yrbYhnr68
-----END CERTIFICATE-----

Hellenic Academic and Research Institutions ECC RootCA 2015
===========================================================
-----BEGIN CERTIFICATE-----
MIICwzCCAkqgAwIBAgIBADAKBggqhkjOPQQDAjCBqjELMAkGA1UEBhMCR1IxDzANBgNVBAcTBkF0
aGVuczFEMEIGA1UEChM7SGVsbGVuaWMgQWNhZGVtaWMgYW5kIFJlc2VhcmNoIEluc3RpdHV0aW9u
cyBDZXJ0LiBBdXRob3JpdHkxRDBCBgNVBAMTO0hlbGxlbmljIEFjYWRlbWljIGFuZCBSZXNlYXJj
aCBJbnN0aXR1dGlvbnMgRUNDIFJvb3RDQSAyMDE1MB4XDTE1MDcwNzEwMzcxMloXDTQwMDYzMDEw
MzcxMlowgaoxCzAJBgNVBAYTAkdSMQ8wDQYDVQQHEwZBdGhlbnMxRDBCBgNVBAoTO0hlbGxlbmlj
IEFjYWRlbWljIGFuZCBSZXNlYXJjaCBJbnN0aXR1dGlvbnMgQ2VydC4gQXV0aG9yaXR5MUQwQgYD
VQQDEztIZWxsZW5pYyBBY2FkZW1pYyBhbmQgUmVzZWFyY2ggSW5zdGl0dXRpb25zIEVDQyBSb290
Q0EgMjAxNTB2MBAGByqGSM49AgEGBSuBBAAiA2IABJKgQehLgoRc4vgxEZmGZE4JJS+dQS8KrjVP
dJWyUWRrjWvmP3CV8AVER6ZyOFB2lQJajq4onvktTpnvLEhvTCUp6NFxW98dwXU3tNf6e3pCnGoK
Vlp8aQuqgAkkbH7BRqNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O
BBYEFLQiC4KZJAEOnLvkDv2/+5cgk5kqMAoGCCqGSM49BAMCA2cAMGQCMGfOFmI4oqxiRaeplSTA
GiecMjvAwNW6qef4BENThe5SId6d9SWDPp5YSy/XZxMOIQIwBeF1Ad5o7SofTUwJCA3sS61kFyjn
dc5FZXIhF8siQQ6ME5g4mlRtm8rifOoCWCKR
-----END CERTIFICATE-----

ISRG Root X1
============
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UE
BhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQD
EwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQG
EwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMT
DElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54r
Vygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj1
3Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8K
b4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCN
Aymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ
4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf
1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFu
hjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQH
usEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/r
OPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4G
A1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY
9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV
0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwt
hDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJw
TdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nx
e5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZA
JzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahD
YVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9n
JEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJ
m+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----

AC RAIZ FNMT-RCM
================
-----BEGIN CERTIFICATE-----
MIIFgzCCA2ugAwIBAgIPXZONMGc2yAYdGsdUhGkHMA0GCSqGSIb3DQEBCwUAMDsxCzAJBgNVBAYT
AkVTMREwDwYDVQQKDAhGTk1ULVJDTTEZMBcGA1UECwwQQUMgUkFJWiBGTk1ULVJDTTAeFw0wODEw
MjkxNTU5NTZaFw0zMDAxMDEwMDAwMDBaMDsxCzAJBgNVBAYTAkVTMREwDwYDVQQKDAhGTk1ULVJD
TTEZMBcGA1UECwwQQUMgUkFJWiBGTk1ULVJDTTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBALpxgHpMhm5/yBNtwMZ9HACXjywMI7sQmkCpGreHiPibVmr75nuOi5KOpyVdWRHbNi63URcf
qQgfBBckWKo3Shjf5TnUV/3XwSyRAZHiItQDwFj8d0fsjz50Q7qsNI1NOHZnjrDIbzAzWHFctPVr
btQBULgTfmxKo0nRIBnuvMApGGWn3v7v3QqQIecaZ5JCEJhfTzC8PhxFtBDXaEAUwED653cXeuYL
j2VbPNmaUtu1vZ5Gzz3rkQUCwJaydkxNEJY7kvqcfw+Z374jNUUeAlz+taibmSXaXvMiwzn15Cou
08YfxGyqxRxqAQVKL9LFwag0Jl1mpdICIfkYtwb1TplvqKtMUejPUBjFd8g5CSxJkjKZqLsXF3mw
WsXmo8RZZUc1g16p6DULmbvkzSDGm0oGObVo/CK67lWMK07q87Hj/LaZmtVC+nFNCM+HHmpxffnT
tOmlcYF7wk5HlqX2doWjKI/pgG6BU6VtX7hI+cL5NqYuSf+4lsKMB7ObiFj86xsc3i1w4peSMKGJ
47xVqCfWS+2QrYv6YyVZLag13cqXM7zlzced0ezvXg5KkAYmY6252TUtB7p2ZSysV4999AeU14EC
ll2jB0nVetBX+RvnU0Z1qrB5QstocQjpYL05ac70r8NWQMetUqIJ5G+GR4of6ygnXYMgrwTJbFaa
i0b1AgMBAAGjgYMwgYAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE
FPd9xf3E6Jobd2Sn9R2gzL+HYJptMD4GA1UdIAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1o
dHRwOi8vd3d3LmNlcnQuZm5tdC5lcy9kcGNzLzANBgkqhkiG9w0BAQsFAAOCAgEAB5BK3/MjTvDD
nFFlm5wioooMhfNzKWtN/gHiqQxjAb8EZ6WdmF/9ARP67Jpi6Yb+tmLSbkyU+8B1RXxlDPiyN8+s
D8+Nb/kZ94/sHvJwnvDKuO+3/3Y3dlv2bojzr2IyIpMNOmqOFGYMLVN0V2Ue1bLdI4E7pWYjJ2cJ
j+F3qkPNZVEI7VFY/uY5+ctHhKQV8Xa7pO6kO8Rf77IzlhEYt8llvhjho6Tc+hj507wTmzl6NLrT
Qfv6MooqtyuGC2mDOL7Nii4LcK2NJpLuHvUBKwrZ1pebbuCoGRw6IYsMHkCtA+fdZn71uSANA+iW
+YJF1DngoABd15jmfZ5nc8OaKveri6E6FO80vFIOiZiaBECEHX5FaZNXzuvO+FB8TxxuBEOb+dY7
Ixjp6o7RTUaN8Tvkasq6+yO3m/qZASlaWFot4/nUbQ4mrcFuNLwy+AwF+mWj2zs3gyLp1txyM/1d
8iC9djwj2ij3+RvrWWTV3F9yfiD8zYm1kGdNYno/Tq0dwzn+evQoFt9B9kiABdcPUXmsEKvU7ANm
5mqwujGSQkBqvjrTcuFqN1W8rB2Vt2lh8kORdOag0wokRqEIr9baRRmW1FMdW4R58MD3R++Lj8UG
rp1MYp3/RgT408m2ECVAdf4WqslKYIYvuu8wd+RU4riEmViAqhOLUTpPSPaLtrM=
-----END CERTIFICATE-----

Amazon Root CA 1
================
-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsFADA5MQswCQYD
VQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAxMB4XDTE1
MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpv
bjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALJ4gHHKeNXjca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgH
FzZM9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qwIFAGbHrQ
gLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6VOujw5H5SNz/0egwLX0t
dHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L93FcXmn/6pUCyziKrlA4b9v7LWIbxcce
VOF34GfID5yHI9Y/QCB/IIDEgEw+OyQmjgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3
DQEBCwUAA4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDIU5PM
CCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUsN+gDS63pYaACbvXy
8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vvo/ufQJVtMVT8QtPHRh8jrdkPSHCa
2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2
xJNDd2ZhwLnoQdeXeGADbkpyrqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----

Amazon Root CA 2
================
-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgITBmyf0pY1hp8KD+WGePhbJruKNzANBgkqhkiG9w0BAQwFADA5MQswCQYD
VQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAyMB4XDTE1
MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpv
bjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBAK2Wny2cSkxKgXlRmeyKy2tgURO8TW0G/LAIjd0ZEGrHJgw12MBvIITplLGbhQPDW9tK6Mj4
kHbZW0/jTOgGNk3Mmqw9DJArktQGGWCsN0R5hYGCrVo34A3MnaZMUnbqQ523BNFQ9lXg1dKmSYXp
N+nKfq5clU1Imj+uIFptiJXZNLhSGkOQsL9sBbm2eLfq0OQ6PBJTYv9K8nu+NQWpEjTj82R0Yiw9
AElaKP4yRLuH3WUnAnE72kr3H9rN9yFVkE8P7K6C4Z9r2UXTu/Bfh+08LDmG2j/e7HJV63mjrdvd
fLC6HM783k81ds8P+HgfajZRRidhW+mez/CiVX18JYpvL7TFz4QuK/0NURBs+18bvBt+xa47mAEx
kv8LV/SasrlX6avvDXbR8O70zoan4G7ptGmh32n2M8ZpLpcTnqWHsFcQgTfJU7O7f/aS0ZzQGPSS
btqDT6ZjmUyl+17vIWR6IF9sZIUVyzfpYgwLKhbcAS4y2j5L9Z469hdAlO+ekQiG+r5jqFoz7Mt0
Q5X5bGlSNscpb/xVA1wf+5+9R+vnSUeVC06JIglJ4PVhHvG/LopyboBZ/1c6+XUyo05f7O0oYtlN
c/LMgRdg7c3r3NunysV+Ar3yVAhU/bQtCSwXVEqY0VThUWcI0u1ufm8/0i2BWSlmy5A5lREedCf+
3euvAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSw
DPBMMPQFWAJI/TPlUq9LhONmUjANBgkqhkiG9w0BAQwFAAOCAgEAqqiAjw54o+Ci1M3m9Zh6O+oA
A7CXDpO8Wqj2LIxyh6mx/H9z/WNxeKWHWc8w4Q0QshNabYL1auaAn6AFC2jkR2vHat+2/XcycuUY
+gn0oJMsXdKMdYV2ZZAMA3m3MSNjrXiDCYZohMr/+c8mmpJ5581LxedhpxfL86kSk5Nrp+gvU5LE
YFiwzAJRGFuFjWJZY7attN6a+yb3ACfAXVU3dJnJUH/jWS5E4ywl7uxMMne0nxrpS10gxdr9HIcW
xkPo1LsmmkVwXqkLN1PiRnsn/eBG8om3zEK2yygmbtmlyTrIQRNg91CMFa6ybRoVGld45pIq2WWQ
gj9sAq+uEjonljYE1x2igGOpm/HlurR8FLBOybEfdF849lHqm/osohHUqS0nGkWxr7JOcQ3AWEbW
aQbLU8uz/mtBzUF+fUwPfHJ5elnNXkoOrJupmHN5fLT0zLm4BwyydFy4x2+IoZCn9Kr5v2c69BoV
Yh63n749sSmvZ6ES8lgQGVMDMBu4Gon2nL2XA46jCfMdiyHxtN/kHNGfZQIG6lzWE7OE76KlXIx3
KadowGuuQNKotOrN8I1LOJwZmhsoVLiJkO/KdYE+HvJkJMcYr07/R54H9jVlpNMKVv/1F2Rs76gi
JUmTtt8AF9pYfl3uxRuw0dFfIRDH+fO6AgonB8Xx1sfT4PsJYGw=
-----END CERTIFICATE-----

Amazon Root CA 3
================
-----BEGIN CERTIFICATE-----
MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5MQswCQYDVQQG
EwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAzMB4XDTE1MDUy
NjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZ
MBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZB
f8ANm+gBG1bG8lKlui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjr
Zt6jQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSrttvXBp43
rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkrBqWTrBqYaGFy+uGh0Psc
eGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteMYyRIHN8wfdVoOw==
-----END CERTIFICATE-----

Amazon Root CA 4
================
-----BEGIN CERTIFICATE-----
MIIB8jCCAXigAwIBAgITBmyf18G7EEwpQ+Vxe3ssyBrBDjAKBggqhkjOPQQDAzA5MQswCQYDVQQG
EwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSA0MB4XDTE1MDUy
NjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZ
MBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN
/sGKe0uoe0ZLY7Bi9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri
83BkM6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAYYwHQYDVR0OBBYEFNPsxzplbszh2naaVvuc84ZtV+WBMAoGCCqGSM49BAMDA2gA
MGUCMDqLIfG9fhGt0O9Yli/W651+kI0rz2ZVwyzjKKlwCkcO8DdZEv8tmZQoTipPNU0zWgIxAOp1
AE47xDqUEpHJWEadIRNyp4iciuRMStuW1KyLa2tJElMzrdfkviT8tQp21KW8EA==
-----END CERTIFICATE-----

TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1
=============================================
-----BEGIN CERTIFICATE-----
MIIEYzCCA0ugAwIBAgIBATANBgkqhkiG9w0BAQsFADCB0jELMAkGA1UEBhMCVFIxGDAWBgNVBAcT
D0dlYnplIC0gS29jYWVsaTFCMEAGA1UEChM5VHVya2l5ZSBCaWxpbXNlbCB2ZSBUZWtub2xvamlr
IEFyYXN0aXJtYSBLdXJ1bXUgLSBUVUJJVEFLMS0wKwYDVQQLEyRLYW11IFNlcnRpZmlrYXN5b24g
TWVya2V6aSAtIEthbXUgU00xNjA0BgNVBAMTLVRVQklUQUsgS2FtdSBTTSBTU0wgS29rIFNlcnRp
ZmlrYXNpIC0gU3VydW0gMTAeFw0xMzExMjUwODI1NTVaFw00MzEwMjUwODI1NTVaMIHSMQswCQYD
VQQGEwJUUjEYMBYGA1UEBxMPR2ViemUgLSBLb2NhZWxpMUIwQAYDVQQKEzlUdXJraXllIEJpbGlt
c2VsIHZlIFRla25vbG9qaWsgQXJhc3Rpcm1hIEt1cnVtdSAtIFRVQklUQUsxLTArBgNVBAsTJEth
bXUgU2VydGlmaWthc3lvbiBNZXJrZXppIC0gS2FtdSBTTTE2MDQGA1UEAxMtVFVCSVRBSyBLYW11
IFNNIFNTTCBLb2sgU2VydGlmaWthc2kgLSBTdXJ1bSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAr3UwM6q7a9OZLBI3hNmNe5eA027n/5tQlT6QlVZC1xl8JoSNkvoBHToP4mQ4t4y8
6Ij5iySrLqP1N+RAjhgleYN1Hzv/bKjFxlb4tO2KRKOrbEz8HdDc72i9z+SqzvBV96I01INrN3wc
wv61A+xXzry0tcXtAA9TNypN9E8Mg/uGz8v+jE69h/mniyFXnHrfA2eJLJ2XYacQuFWQfw4tJzh0
3+f92k4S400VIgLI4OD8D62K18lUUMw7D8oWgITQUVbDjlZ/iSIzL+aFCr2lqBs23tPcLG07xxO9
WSMs5uWk99gL7eqQQESolbuT1dCANLZGeA4fAJNG4e7p+exPFwIDAQABo0IwQDAdBgNVHQ4EFgQU
ZT/HiobGPN08VFw1+DrtUgxHV8gwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
KoZIhvcNAQELBQADggEBACo/4fEyjq7hmFxLXs9rHmoJ0iKpEsdeV31zVmSAhHqT5Am5EM2fKifh
AHe+SMg1qIGf5LgsyX8OsNJLN13qudULXjS99HMpw+0mFZx+CFOKWI3QSyjfwbPfIPP54+M638yc
lNhOT8NrF7f3cuitZjO1JVOr4PhMqZ398g26rrnZqsZr+ZO7rqu4lzwDGrpDxpa5RXI4s6ehlj2R
e37AIVNMh+3yC1SVUZPVIqUNivGTDj5UDrDYyU7c8jEyVupk+eq1nRZmQnLzf9OxMUP8pI4X8W0j
q5Rm+K37DwhuJi1/FwcJsoz7UMCflo3Ptv0AnVoUmr8CRPXBwp8iXqIPoeM=
-----END CERTIFICATE-----

GDCA TrustAUTH R5 ROOT
======================
-----BEGIN CERTIFICATE-----
MIIFiDCCA3CgAwIBAgIIfQmX/vBH6nowDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCQ04xMjAw
BgNVBAoMKUdVQU5HIERPTkcgQ0VSVElGSUNBVEUgQVVUSE9SSVRZIENPLixMVEQuMR8wHQYDVQQD
DBZHRENBIFRydXN0QVVUSCBSNSBST09UMB4XDTE0MTEyNjA1MTMxNVoXDTQwMTIzMTE1NTk1OVow
YjELMAkGA1UEBhMCQ04xMjAwBgNVBAoMKUdVQU5HIERPTkcgQ0VSVElGSUNBVEUgQVVUSE9SSVRZ
IENPLixMVEQuMR8wHQYDVQQDDBZHRENBIFRydXN0QVVUSCBSNSBST09UMIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEA2aMW8Mh0dHeb7zMNOwZ+Vfy1YI92hhJCfVZmPoiC7XJjDp6L3TQs
AlFRwxn9WVSEyfFrs0yw6ehGXTjGoqcuEVe6ghWinI9tsJlKCvLriXBjTnnEt1u9ol2x8kECK62p
OqPseQrsXzrj/e+APK00mxqriCZ7VqKChh/rNYmDf1+uKU49tm7srsHwJ5uu4/Ts765/94Y9cnrr
pftZTqfrlYwiOXnhLQiPzLyRuEH3FMEjqcOtmkVEs7LXLM3GKeJQEK5cy4KOFxg2fZfmiJqwTTQJ
9Cy5WmYqsBebnh52nUpmMUHfP/vFBu8btn4aRjb3ZGM74zkYI+dndRTVdVeSN72+ahsmUPI2JgaQ
xXABZG12ZuGR224HwGGALrIuL4xwp9E7PLOR5G62xDtw8mySlwnNR30YwPO7ng/Wi64HtloPzgsM
R6flPri9fcebNaBhlzpBdRfMK5Z3KpIhHtmVdiBnaM8Nvd/WHwlqmuLMc3GkL30SgLdTMEZeS1SZ
D2fJpcjyIMGC7J0R38IC+xo70e0gmu9lZJIQDSri3nDxGGeCjGHeuLzRL5z7D9Ar7Rt2ueQ5Vfj4
oR24qoAATILnsn8JuLwwoC8N9VKejveSswoAHQBUlwbgsQfZxw9cZX08bVlX5O2ljelAU58VS6Bx
9hoh49pwBiFYFIeFd3mqgnkCAwEAAaNCMEAwHQYDVR0OBBYEFOLJQJ9NzuiaoXzPDj9lxSmIahlR
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQDRSVfg
p8xoWLoBDysZzY2wYUWsEe1jUGn4H3++Fo/9nesLqjJHdtJnJO29fDMylyrHBYZmDRd9FBUb1Ov9
H5r2XpdptxolpAqzkT9fNqyL7FeoPueBihhXOYV0GkLH6VsTX4/5COmSdI31R9KrO9b7eGZONn35
6ZLpBN79SWP8bfsUcZNnL0dKt7n/HipzcEYwv1ryL3ml4Y0M2fmyYzeMN2WFcGpcWwlyua1jPLHd
+PwyvzeG5LuOmCd+uh8W4XAR8gPfJWIyJyYYMoSf/wA6E7qaTfRPuBRwIrHKK5DOKcFw9C+df/KQ
HtZa37dG/OaG+svgIHZ6uqbL9XzeYqWxi+7egmaKTjowHz+Ay60nugxe19CxVsp3cbK1daFQqUBD
F8Io2c9Si1vIY9RCPqAzekYu9wogRlR+ak8x8YF+QnQ4ZXMn7sZ8uI7XpTrXmKGcjBBV09tL7ECQ
8s1uV9JiDnxXk7Gnbc2dg7sq5+W2O3FYrf3RRbxake5TFW/TRQl1brqQXR4EzzffHqhmsYzmIGrv
/EhOdJhCrylvLmrH+33RZjEizIYAfmaDDEL0vTSSwxrqT8p+ck0LcIymSLumoRT2+1hEmRSuqguT
aaApJUqlyyvdimYHFngVV3Eb7PVHhPOeMTd61X8kreS8/f3MboPoDKi3QWwH3b08hpcv0g==
-----END CERTIFICATE-----

TrustCor RootCert CA-1
======================
-----BEGIN CERTIFICATE-----
MIIEMDCCAxigAwIBAgIJANqb7HHzA7AZMA0GCSqGSIb3DQEBCwUAMIGkMQswCQYDVQQGEwJQQTEP
MA0GA1UECAwGUGFuYW1hMRQwEgYDVQQHDAtQYW5hbWEgQ2l0eTEkMCIGA1UECgwbVHJ1c3RDb3Ig
U3lzdGVtcyBTLiBkZSBSLkwuMScwJQYDVQQLDB5UcnVzdENvciBDZXJ0aWZpY2F0ZSBBdXRob3Jp
dHkxHzAdBgNVBAMMFlRydXN0Q29yIFJvb3RDZXJ0IENBLTEwHhcNMTYwMjA0MTIzMjE2WhcNMjkx
MjMxMTcyMzE2WjCBpDELMAkGA1UEBhMCUEExDzANBgNVBAgMBlBhbmFtYTEUMBIGA1UEBwwLUGFu
YW1hIENpdHkxJDAiBgNVBAoMG1RydXN0Q29yIFN5c3RlbXMgUy4gZGUgUi5MLjEnMCUGA1UECwwe
VHJ1c3RDb3IgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MR8wHQYDVQQDDBZUcnVzdENvciBSb290Q2Vy
dCBDQS0xMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv463leLCJhJrMxnHQFgKq1mq
jQCj/IDHUHuO1CAmujIS2CNUSSUQIpidRtLByZ5OGy4sDjjzGiVoHKZaBeYei0i/mJZ0PmnK6bV4
pQa81QBeCQryJ3pS/C3Vseq0iWEk8xoT26nPUu0MJLq5nux+AHT6k61sKZKuUbS701e/s/OojZz0
JEsq1pme9J7+wH5COucLlVPat2gOkEz7cD+PSiyU8ybdY2mplNgQTsVHCJCZGxdNuWxu72CVEY4h
gLW9oHPY0LJ3xEXqWib7ZnZ2+AYfYW0PVcWDtxBWcgYHpfOxGgMFZA6dWorWhnAbJN7+KIor0Gqw
/Hqi3LJ5DotlDwIDAQABo2MwYTAdBgNVHQ4EFgQU7mtJPHo/DeOxCbeKyKsZn3MzUOcwHwYDVR0j
BBgwFoAU7mtJPHo/DeOxCbeKyKsZn3MzUOcwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwDQYJKoZIhvcNAQELBQADggEBACUY1JGPE+6PHh0RU9otRCkZoB5rMZ5NDp6tPVxBb5UrJKF5
mDo4Nvu7Zp5I/5CQ7z3UuJu0h3U/IJvOcs+hVcFNZKIZBqEHMwwLKeXx6quj7LUKdJDHfXLy11yf
ke+Ri7fc7Waiz45mO7yfOgLgJ90WmMCV1Aqk5IGadZQ1nJBfiDcGrVmVCrDRZ9MZyonnMlo2HD6C
qFqTvsbQZJG2z9m2GM/bftJlo6bEjhcxwft+dtvTheNYsnd6djtsL1Ac59v2Z3kf9YKVmgenFK+P
3CghZwnS1k1aHBkcjndcw5QkPTJrS37UeJSDvjdNzl/HHk484IkzlQsPpTLWPFp5LBk=
-----END CERTIFICATE-----

TrustCor RootCert CA-2
======================
-----BEGIN CERTIFICATE-----
MIIGLzCCBBegAwIBAgIIJaHfyjPLWQIwDQYJKoZIhvcNAQELBQAwgaQxCzAJBgNVBAYTAlBBMQ8w
DQYDVQQIDAZQYW5hbWExFDASBgNVBAcMC1BhbmFtYSBDaXR5MSQwIgYDVQQKDBtUcnVzdENvciBT
eXN0ZW1zIFMuIGRlIFIuTC4xJzAlBgNVBAsMHlRydXN0Q29yIENlcnRpZmljYXRlIEF1dGhvcml0
eTEfMB0GA1UEAwwWVHJ1c3RDb3IgUm9vdENlcnQgQ0EtMjAeFw0xNjAyMDQxMjMyMjNaFw0zNDEy
MzExNzI2MzlaMIGkMQswCQYDVQQGEwJQQTEPMA0GA1UECAwGUGFuYW1hMRQwEgYDVQQHDAtQYW5h
bWEgQ2l0eTEkMCIGA1UECgwbVHJ1c3RDb3IgU3lzdGVtcyBTLiBkZSBSLkwuMScwJQYDVQQLDB5U
cnVzdENvciBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxHzAdBgNVBAMMFlRydXN0Q29yIFJvb3RDZXJ0
IENBLTIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCnIG7CKqJiJJWQdsg4foDSq8Gb
ZQWU9MEKENUCrO2fk8eHyLAnK0IMPQo+QVqedd2NyuCb7GgypGmSaIwLgQ5WoD4a3SwlFIIvl9Nk
RvRUqdw6VC0xK5mC8tkq1+9xALgxpL56JAfDQiDyitSSBBtlVkxs1Pu2YVpHI7TYabS3OtB0PAx1
oYxOdqHp2yqlO/rOsP9+aij9JxzIsekp8VduZLTQwRVtDr4uDkbIXvRR/u8OYzo7cbrPb1nKDOOb
XUm4TOJXsZiKQlecdu/vvdFoqNL0Cbt3Nb4lggjEFixEIFapRBF37120Hapeaz6LMvYHL1cEksr1
/p3C6eizjkxLAjHZ5DxIgif3GIJ2SDpxsROhOdUuxTTCHWKF3wP+TfSvPd9cW436cOGlfifHhi5q
jxLGhF5DUVCcGZt45vz27Ud+ez1m7xMTiF88oWP7+ayHNZ/zgp6kPwqcMWmLmaSISo5uZk3vFsQP
eSghYA2FFn3XVDjxklb9tTNMg9zXEJ9L/cb4Qr26fHMC4P99zVvh1Kxhe1fVSntb1IVYJ12/+Ctg
rKAmrhQhJ8Z3mjOAPF5GP/fDsaOGM8boXg25NSyqRsGFAnWAoOsk+xWq5Gd/bnc/9ASKL3x74xdh
8N0JqSDIvgmk0H5Ew7IwSjiqqewYmgeCK9u4nBit2uBGF6zPXQIDAQABo2MwYTAdBgNVHQ4EFgQU
2f4hQG6UnrybPZx9mCAZ5YwwYrIwHwYDVR0jBBgwFoAU2f4hQG6UnrybPZx9mCAZ5YwwYrIwDwYD
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggIBAJ5Fngw7tu/h
Osh80QA9z+LqBrWyOrsGS2h60COXdKcs8AjYeVrXWoSK2BKaG9l9XE1wxaX5q+WjiYndAfrs3fnp
kpfbsEZC89NiqpX+MWcUaViQCqoL7jcjx1BRtPV+nuN79+TMQjItSQzL/0kMmx40/W5ulop5A7Zv
2wnL/V9lFDfhOPXzYRZY5LVtDQsEGz9QLX+zx3oaFoBg+Iof6Rsqxvm6ARppv9JYx1RXCI/hOWB3
S6xZhBqI8d3LT3jX5+EzLfzuQfogsL7L9ziUwOHQhQ+77Sxzq+3+knYaZH9bDTMJBzN7Bj8RpFxw
PIXAz+OQqIN3+tvmxYxoZxBnpVIt8MSZj3+/0WvitUfW2dCFmU2Umw9Lje4AWkcdEQOsQRivh7dv
DDqPys/cA8GiCcjl/YBeyGBCARsaU1q7N6a3vLqE6R5sGtRk2tRD/pOLS/IseRYQ1JMLiI+h2IYU
RpFHmygk71dSTlxCnKr3Sewn6EAes6aJInKc9Q0ztFijMDvd1GpUk74aTfOTlPf8hAs/hCBcNANE
xdqtvArBAs8e5ZTZ845b2EzwnexhF7sUMlQMAimTHpKG9n/v55IFDlndmQguLvqcAFLTxWYp5KeX
RKQOKIETNcX2b2TmQcTVL8w0RSXPQQCWPUouwpaYT05KnJe32x+SMsj/D1Fu1uwJ
-----END CERTIFICATE-----

TrustCor ECA-1
==============
-----BEGIN CERTIFICATE-----
MIIEIDCCAwigAwIBAgIJAISCLF8cYtBAMA0GCSqGSIb3DQEBCwUAMIGcMQswCQYDVQQGEwJQQTEP
MA0GA1UECAwGUGFuYW1hMRQwEgYDVQQHDAtQYW5hbWEgQ2l0eTEkMCIGA1UECgwbVHJ1c3RDb3Ig
U3lzdGVtcyBTLiBkZSBSLkwuMScwJQYDVQQLDB5UcnVzdENvciBDZXJ0aWZpY2F0ZSBBdXRob3Jp
dHkxFzAVBgNVBAMMDlRydXN0Q29yIEVDQS0xMB4XDTE2MDIwNDEyMzIzM1oXDTI5MTIzMTE3Mjgw
N1owgZwxCzAJBgNVBAYTAlBBMQ8wDQYDVQQIDAZQYW5hbWExFDASBgNVBAcMC1BhbmFtYSBDaXR5
MSQwIgYDVQQKDBtUcnVzdENvciBTeXN0ZW1zIFMuIGRlIFIuTC4xJzAlBgNVBAsMHlRydXN0Q29y
IENlcnRpZmljYXRlIEF1dGhvcml0eTEXMBUGA1UEAwwOVHJ1c3RDb3IgRUNBLTEwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPj+ARtZ+odnbb3w9U73NjKYKtR8aja+3+XzP4Q1HpGjOR
MRegdMTUpwHmspI+ap3tDvl0mEDTPwOABoJA6LHip1GnHYMma6ve+heRK9jGrB6xnhkB1Zem6g23
xFUfJ3zSCNV2HykVh0A53ThFEXXQmqc04L/NyFIduUd+Dbi7xgz2c1cWWn5DkR9VOsZtRASqnKmc
p0yJF4OuowReUoCLHhIlERnXDH19MURB6tuvsBzvgdAsxZohmz3tQjtQJvLsznFhBmIhVE5/wZ0+
fyCMgMsq2JdiyIMzkX2woloPV+g7zPIlstR8L+xNxqE6FXrntl019fZISjZFZtS6mFjBAgMBAAGj
YzBhMB0GA1UdDgQWBBREnkj1zG1I1KBLf/5ZJC+Dl5mahjAfBgNVHSMEGDAWgBREnkj1zG1I1KBL
f/5ZJC+Dl5mahjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsF
AAOCAQEABT41XBVwm8nHc2FvcivUwo/yQ10CzsSUuZQRg2dd4mdsdXa/uwyqNsatR5Nj3B5+1t4u
/ukZMjgDfxT2AHMsWbEhBuH7rBiVDKP/mZb3Kyeb1STMHd3BOuCYRLDE5D53sXOpZCz2HAF8P11F
hcCF5yWPldwX8zyfGm6wyuMdKulMY/okYWLW2n62HGz1Ah3UKt1VkOsqEUc8Ll50soIipX1TH0Xs
J5F95yIW6MBoNtjG8U+ARDL54dHRHareqKucBK+tIA5kmE2la8BIWJZpTdwHjFGTot+fDz2LYLSC
jaoITmJF4PkL0uDgPFveXHEnJcLmA4GLEFPjx1WitJ/X5g==
-----END CERTIFICATE-----

SSL.com Root Certification Authority RSA
========================================
-----BEGIN CERTIFICATE-----
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
WuuA8ShYIc2wBlX7Jz9TkHCpBB5XJ7k=
-----END CERTIFICATE-----

SSL.com Root Certification Authority ECC
========================================
-----BEGIN CERTIFICATE-----
MIICjTCCAhSgAwIBAgIIdebfy8FoW6gwCgYIKoZIzj0EAwIwfDELMAkGA1UEBhMCVVMxDjAMBgNV
BAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9TU0wgQ29ycG9yYXRpb24xMTAv
BgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBFQ0MwHhcNMTYwMjEy
MTgxNDAzWhcNNDEwMjEyMTgxNDAzWjB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAO
BgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNv
bSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IEVDQzB2MBAGByqGSM49AgEGBSuBBAAiA2IA
BEVuqVDEpiM2nl8ojRfLliJkP9x6jh3MCLOicSS6jkm5BBtHllirLZXI7Z4INcgn64mMU1jrYor+
8FsPazFSY0E7ic3s7LaNGdM0B9y7xgZ/wkWV7Mt/qCPgCemB+vNH06NjMGEwHQYDVR0OBBYEFILR
hXMw5zUE044CkvvlpNHEIejNMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUgtGFczDnNQTT
jgKS++Wk0cQh6M0wDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA2cAMGQCMG/n61kRpGDPYbCW
e+0F+S8Tkdzt5fxQaxFGRrMcIQBiu77D5+jNB5n5DQtdcj7EqgIwH7y6C+IwJPt8bYBVCpk+gA0z
5Wajs6O7pdWLjwkspl1+4vAHCGht0nxpbl/f5Wpl
-----END CERTIFICATE-----

SSL.com EV Root Certification Authority RSA R2
==============================================
-----BEGIN CERTIFICATE-----
MIIF6zCCA9OgAwIBAgIIVrYpzTS8ePYwDQYJKoZIhvcNAQELBQAwgYIxCzAJBgNVBAYTAlVTMQ4w
DAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9u
MTcwNQYDVQQDDC5TU0wuY29tIEVWIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUlNBIFIy
MB4XDTE3MDUzMTE4MTQzN1oXDTQyMDUzMDE4MTQzN1owgYIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQI
DAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMTcwNQYD
VQQDDC5TU0wuY29tIEVWIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUlNBIFIyMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjzZlQOHWTcDXtOlG2mvqM0fNTPl9fb69LT3w23jh
hqXZuglXaO1XPqDQCEGD5yhBJB/jchXQARr7XnAjssufOePPxU7Gkm0mxnu7s9onnQqG6YE3Bf7w
cXHswxzpY6IXFJ3vG2fThVUCAtZJycxa4bH3bzKfydQ7iEGonL3Lq9ttewkfokxykNorCPzPPFTO
Zw+oz12WGQvE43LrrdF9HSfvkusQv1vrO6/PgN3B0pYEW3p+pKk8OHakYo6gOV7qd89dAFmPZiw+
B6KjBSYRaZfqhbcPlgtLyEDhULouisv3D5oi53+aNxPN8k0TayHRwMwi8qFG9kRpnMphNQcAb9Zh
CBHqurj26bNg5U257J8UZslXWNvNh2n4ioYSA0e/ZhN2rHd9NCSFg83XqpyQGp8hLH94t2S42Oim
9HizVcuE0jLEeK6jj2HdzghTreyI/BXkmg3mnxp3zkyPuBQVPWKchjgGAGYS5Fl2WlPAApiiECto
RHuOec4zSnaqW4EWG7WK2NAAe15itAnWhmMOpgWVSbooi4iTsjQc2KRVbrcc0N6ZVTsj9CLg+Slm
JuwgUHfbSguPvuUCYHBBXtSuUDkiFCbLsjtzdFVHB3mBOagwE0TlBIqulhMlQg+5U8Sb/M3kHN48
+qvWBkofZ6aYMBzdLNvcGJVXZsb/XItW9XcCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
HSMEGDAWgBT5YLvU49U09rj1BoAlp3PbRmmonjAdBgNVHQ4EFgQU+WC71OPVNPa49QaAJadz20Zp
qJ4wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQBWs47LCp1Jjr+kxJG7ZhcFUZh1
++VQLHqe8RT6q9OKPv+RKY9ji9i0qVQBDb6Thi/5Sm3HXvVX+cpVHBK+Rw82xd9qt9t1wkclf7nx
Y/hoLVUE0fKNsKTPvDxeH3jnpaAgcLAExbf3cqfeIg29MyVGjGSSJuM+LmOW2puMPfgYCdcDzH2G
guDKBAdRUNf/ktUM79qGn5nX67evaOI5JpS6aLe/g9Pqemc9YmeuJeVy6OLk7K4S9ksrPJ/psEDz
OFSz/bdoyNrGj1E8svuR3Bznm53htw1yj+KkxKl4+esUrMZDBcJlOSgYAsOCsp0FvmXtll9ldDz7
CTUue5wT/RsPXcdtgTpWD8w74a8CLyKsRspGPKAcTNZEtF4uXBVmCeEmKf7GUmG6sXP/wwyc5Wxq
lD8UykAWlYTzWamsX0xhk23RO8yilQwipmdnRC652dKKQbNmC1r7fSOl8hqw/96bg5Qu0T/fkreR
rwU7ZcegbLHNYhLDkBvjJc40vG93drEQw/cFGsDWr3RiSBd3kmmQYRzelYB0VI8YHMPzA9C/pEN1
hlMYegouCRw2n5H9gooiS9EOUCXdywMMF8mDAAhONU2Ki+3wApRmLER/y5UnlhetCTCstnEXbosX
9hwJ1C07mKVx01QT2WDz9UtmT/rx7iASjbSsV7FFY6GsdqnC+w==
-----END CERTIFICATE-----

SSL.com EV Root Certification Authority ECC
===========================================
-----BEGIN CERTIFICATE-----
MIIClDCCAhqgAwIBAgIILCmcWxbtBZUwCgYIKoZIzj0EAwIwfzELMAkGA1UEBhMCVVMxDjAMBgNV
BAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9TU0wgQ29ycG9yYXRpb24xNDAy
BgNVBAMMK1NTTC5jb20gRVYgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBFQ0MwHhcNMTYw
MjEyMTgxNTIzWhcNNDEwMjEyMTgxNTIzWjB/MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMx
EDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjE0MDIGA1UEAwwrU1NM
LmNvbSBFViBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IEVDQzB2MBAGByqGSM49AgEGBSuB
BAAiA2IABKoSR5CYG/vvw0AHgyBO8TCCogbR8pKGYfL2IWjKAMTH6kMAVIbc/R/fALhBYlzccBYy
3h+Z1MzFB8gIH2EWB1E9fVwHU+M1OIzfzZ/ZLg1KthkuWnBaBu2+8KGwytAJKaNjMGEwHQYDVR0O
BBYEFFvKXuXe0oGqzagtZFG22XKbl+ZPMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUW8pe
5d7SgarNqC1kUbbZcpuX5k8wDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA2gAMGUCMQCK5kCJ
N+vp1RPZytRrJPOwPYdGWBrssd9v+1a6cGvHOMzosYxPD/fxZ3YOg9AeUY8CMD32IygmTMZgh5Mm
m7I1HrrW9zzRHM76JTymGoEVW/MSD2zuZYrJh6j5B+BimoxcSg==
-----END CERTIFICATE-----

GlobalSign Root CA - R6
=======================
-----BEGIN CERTIFICATE-----
MIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMX
R2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkds
b2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9i
YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFs
U2lnbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQss
grRIxutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToVBu1kZguSgMpE
3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqKGoC3GYEOfsSKvGRMIRxDaNc9PIrFsmbVkJq3MQbF
vuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n16qIfKtJwLnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqM
PKq0pPbzlUoSB239jLKJz9CgYXfIWHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+
azayOeSsJDa38O+2HBNXk7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiWm05O
WgtH8wY2SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+7o/hbguy
CLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUdnjqGBQCe24DWJfncBZ4nWUx2OVvq+aWh2IMP
0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWzjMpYrZxCRXluDocZXFSxZba/jJvcE+kN
b7gu3GduyYsRtYQUigAZcIN5kZeR1BonvzceMgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQE
AwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToDAfBgNV
HSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9lVLN
nsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcWc+ZfwFSY1XS+wc3iEZGtIxg93eFyRJa0
lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5Mr6155wsTLxDKZmOMNOsIeDjHfrY
BzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm8tLjvUYAGm0CuiVdjaExUd1URhxN25mW7xocBFym
Fe944Hn+Xds+qkxV/ZoVqW/hpvvfcDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68KnyBr
3TsTjxKM4kEaSHpzoHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB1
0jZpnOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTOwY3WzvUy2MmeFe8nI+z1TIvWfspA9MRf/T
uTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt9x+vJJUEeKgDu+6B5dpffItK
oZB0JaezPkvILFa9x8jvOOJckvB595yEunQtYQEgfn7R8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+t
JDfLRVpOoERIyNiwmcUVhAn21klJwGW45hpxbqCo8YLoRT5s1gLXCmeDBVrJpBA=
-----END CERTIFICATE-----

OISTE WISeKey Global Root GC CA
===============================
-----BEGIN CERTIFICATE-----
MIICaTCCAe+gAwIBAgIQISpWDK7aDKtARb8roi066jAKBggqhkjOPQQDAzBtMQswCQYDVQQGEwJD
SDEQMA4GA1UEChMHV0lTZUtleTEiMCAGA1UECxMZT0lTVEUgRm91bmRhdGlvbiBFbmRvcnNlZDEo
MCYGA1UEAxMfT0lTVEUgV0lTZUtleSBHbG9iYWwgUm9vdCBHQyBDQTAeFw0xNzA1MDkwOTQ4MzRa
Fw00MjA1MDkwOTU4MzNaMG0xCzAJBgNVBAYTAkNIMRAwDgYDVQQKEwdXSVNlS2V5MSIwIAYDVQQL
ExlPSVNURSBGb3VuZGF0aW9uIEVuZG9yc2VkMSgwJgYDVQQDEx9PSVNURSBXSVNlS2V5IEdsb2Jh
bCBSb290IEdDIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETOlQwMYPchi82PG6s4nieUqjFqdr
VCTbUf/q9Akkwwsin8tqJ4KBDdLArzHkdIJuyiXZjHWd8dvQmqJLIX4Wp2OQ0jnUsYd4XxiWD1Ab
NTcPasbc2RNNpI6QN+a9WzGRo1QwUjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUSIcUrOPDnpBgOtfKie7TrYy0UGYwEAYJKwYBBAGCNxUBBAMCAQAwCgYIKoZIzj0E
AwMDaAAwZQIwJsdpW9zV57LnyAyMjMPdeYwbY9XJUpROTYJKcx6ygISpJcBMWm1JKWB4E+J+SOtk
AjEA2zQgMgj/mkkCtojeFK9dbJlxjRo/i9fgojaGHAeCOnZT/cKi7e97sIBPWA9LUzm9
-----END CERTIFICATE-----

GTS Root R1
===========
-----BEGIN CERTIFICATE-----
MIIFWjCCA0KgAwIBAgIQbkepxUtHDA3sM9CJuRz04TANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQG
EwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJv
b3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAG
A1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx
9vaMf/vo27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7wCl7r
aKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjwTcLCeoiKu7rPWRnW
r4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0PfyblqAj+lug8aJRT7oM6iCsVlgmy4HqM
LnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaHszVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly
4cpk9+aCEI3oncKKiPo4Zor8Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr
06zqkUspzBmkMiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70paDPvOmbsB4om
3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrNVjzRlwW5y0vtOUucxD/SVRNu
JLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEM
BQADggIBADiWCu49tJYeX++dnAsznyvgyv3SjgofQXSlfKqE1OXyHuY3UjKcC9FhHb8owbZEKTV1
d5iyfNm9dKyKaOOpMQkpAWBz40d8U6iQSifvS9efk+eCNs6aaAyC58/UEBZvXw6ZXPYfcX3v73sv
fuo21pdwCxXu11xWajOl40k4DLh9+42FpLFZXvRq4d2h9mREruZRgyFmxhE+885H7pwoHyXa/6xm
ld01D1zvICxi/ZG6qcz8WpyTgYMpl0p8WnK0OdC3d8t5/Wk6kjftbjhlRn7pYL15iJdfOBL07q9b
gsiG1eGZbYwE8na6SfZu6W0eX6DvJ4J2QPim01hcDyxC2kLGe4g0x8HYRZvBPsVhHdljUEn2NIVq
4BjFbkerQUIpm/ZgDdIx02OYI5NaAIFItO/Nis3Jz5nu2Z6qNuFoS3FJFDYoOj0dzpqPJeaAcWEr
tXvM+SUWgeExX6GjfhaknBZqlxi9dnKlC54dNuYvoS++cJEPqOba+MSSQGwlfnuzCdyyF62ARPBo
pY+Udf90WuioAnwMCeKpSwughQtiue+hMZL77/ZRBIls6Kl0obsXs7X9SQ98POyDGCBDTtWTurQ0
sR8WNh8M5mQ5Fkzc4P4dyKliPUDqysU0ArSuiYgzNdwsE3PYJ/HQcu51OyLemGhmW/HGY0dVHLql
CFF1pkgl
-----END CERTIFICATE-----

GTS Root R2
===========
-----BEGIN CERTIFICATE-----
MIIFWjCCA0KgAwIBAgIQbkepxlqz5yDFMJo/aFLybzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQG
EwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJv
b3QgUjIwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAG
A1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjIwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDO3v2m++zsFDQ8BwZabFn3GTXd98GdVarTzTuk
k3LvCvptnfbwhYBboUhSnznFt+4orO/LdmgUud+tAWyZH8QiHZ/+cnfgLFuv5AS/T3KgGjSY6Dlo
7JUle3ah5mm5hRm9iYz+re026nO8/4Piy33B0s5Ks40FnotJk9/BW9BuXvAuMC6C/Pq8tBcKSOWI
m8Wba96wyrQD8Nr0kLhlZPdcTK3ofmZemde4wj7I0BOdre7kRXuJVfeKH2JShBKzwkCX44ofR5Gm
dFrS+LFjKBC4swm4VndAoiaYecb+3yXuPuWgf9RhD1FLPD+M2uFwdNjCaKH5wQzpoeJ/u1U8dgbu
ak7MkogwTZq9TwtImoS1mKPV+3PBV2HdKFZ1E66HjucMUQkQdYhMvI35ezzUIkgfKtzra7tEscsz
cTJGr61K8YzodDqs5xoic4DSMPclQsciOzsSrZYuxsN2B6ogtzVJV+mSSeh2FnIxZyuWfoqjx5RW
Ir9qS34BIbIjMt/kmkRtWVtd9QCgHJvGeJeNkP+byKq0rxFROV7Z+2et1VsRnTKaG73Vululycsl
aVNVJ1zgyjbLiGH7HrfQy+4W+9OmTN6SpdTi3/UGVN4unUu0kzCqgc7dGtxRcw1PcOnlthYhGXmy
5okLdWTK1au8CcEYof/UVKGFPP0UJAOyh9OktwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUu//KjiOfT5nK2+JopqUVJxce2Q4wDQYJKoZIhvcNAQEM
BQADggIBALZp8KZ3/p7uC4Gt4cCpx/k1HUCCq+YEtN/L9x0Pg/B+E02NjO7jMyLDOfxA325BS0JT
vhaI8dI4XsRomRyYUpOM52jtG2pzegVATX9lO9ZY8c6DR2Dj/5epnGB3GFW1fgiTz9D2PGcDFWEJ
+YF59exTpJ/JjwGLc8R3dtyDovUMSRqodt6Sm2T4syzFJ9MHwAiApJiS4wGWAqoC7o87xdFtCjMw
c3i5T1QWvwsHoaRc5svJXISPD+AVdyx+Jn7axEvbpxZ3B7DNdehyQtaVhJ2Gg/LkkM0JR9SLA3Da
WsYDQvTtN6LwG1BUSw7YhN4ZKJmBR64JGz9I0cNv4rBgF/XuIwKl2gBbbZCr7qLpGzvpx0QnRY5r
n/WkhLx3+WuXrD5RRaIRpsyF7gpo8j5QOHokYh4XIDdtak23CZvJ/KRY9bb7nE4Yu5UC56Gtmwfu
Nmsk0jmGwZODUNKBRqhfYlcsu2xkiAhu7xNUX90txGdj08+JN7+dIPT7eoOboB6BAFDC5AwiWVIQ
7UNWhwD4FFKnHYuTjKJNRn8nxnGbJN7k2oaLDX5rIMHAnuFl2GqjpuiFizoHCBy69Y9Vmhh1fuXs
gWbRIXOhNUQLgD1bnF5vKheW0YMjiGZt5obicDIvUiLnyOd/xCxgXS/Dr55FBcOEArf9LAhST4Ld
o/DUhgkC
-----END CERTIFICATE-----

GTS Root R3
===========
-----BEGIN CERTIFICATE-----
MIICDDCCAZGgAwIBAgIQbkepx2ypcyRAiQ8DVd2NHTAKBggqhkjOPQQDAzBHMQswCQYDVQQGEwJV
UzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3Qg
UjMwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UE
ChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjMwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAAQfTzOHMymKoYTey8chWEGJ6ladK0uFxh1MJ7x/JlFyb+Kf1qPKzEUU
Rout736GjOyxfi//qXGdGIRFBEFVbivqJn+7kAHjSxm65FSWRQmx1WyRRK2EE46ajA2ADDL24Cej
QjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTB8Sa6oC2uhYHP
0/EqEr24Cmf9vDAKBggqhkjOPQQDAwNpADBmAjEAgFukfCPAlaUs3L6JbyO5o91lAFJekazInXJ0
glMLfalAvWhgxeG4VDvBNhcl2MG9AjEAnjWSdIUlUfUk7GRSJFClH9voy8l27OyCbvWFGFPouOOa
KaqW04MjyaR7YbPMAuhd
-----END CERTIFICATE-----

GTS Root R4
===========
-----BEGIN CERTIFICATE-----
MIICCjCCAZGgAwIBAgIQbkepyIuUtui7OyrYorLBmTAKBggqhkjOPQQDAzBHMQswCQYDVQQGEwJV
UzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3Qg
UjQwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UE
ChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAATzdHOnaItgrkO4NcWBMHtLSZ37wWHO5t5GvWvVYRg1rkDdc/eJkTBa
6zzuhXyiQHY7qca4R9gq55KRanPpsXI5nymfopjTX15YhmUPoYRlBtHci8nHc8iMai/lxKvRHYqj
QjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSATNbrdP9JNqPV
2Py1PsVq8JQdjDAKBggqhkjOPQQDAwNnADBkAjBqUFJ0CMRw3J5QdCHojXohw0+WbhXRIjVhLfoI
N+4Zba3bssx9BzT1YBkstTTZbyACMANxsbqjYAuG7ZoIapVon+Kz4ZNkfF6Tpt95LY2F45TPI11x
zPKwTdb+mciUqXWi4w==
-----END CERTIFICATE-----

UCA Global G2 Root
==================
-----BEGIN CERTIFICATE-----
MIIFRjCCAy6gAwIBAgIQXd+x2lqj7V2+WmUgZQOQ7zANBgkqhkiG9w0BAQsFADA9MQswCQYDVQQG
EwJDTjERMA8GA1UECgwIVW5pVHJ1c3QxGzAZBgNVBAMMElVDQSBHbG9iYWwgRzIgUm9vdDAeFw0x
NjAzMTEwMDAwMDBaFw00MDEyMzEwMDAwMDBaMD0xCzAJBgNVBAYTAkNOMREwDwYDVQQKDAhVbmlU
cnVzdDEbMBkGA1UEAwwSVUNBIEdsb2JhbCBHMiBSb290MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAxeYrb3zvJgUno4Ek2m/LAfmZmqkywiKHYUGRO8vDaBsGxUypK8FnFyIdK+35KYmT
oni9kmugow2ifsqTs6bRjDXVdfkX9s9FxeV67HeToI8jrg4aA3++1NDtLnurRiNb/yzmVHqUwCoV
8MmNsHo7JOHXaOIxPAYzRrZUEaalLyJUKlgNAQLx+hVRZ2zA+te2G3/RVogvGjqNO7uCEeBHANBS
h6v7hn4PJGtAnTRnvI3HLYZveT6OqTwXS3+wmeOwcWDcC/Vkw85DvG1xudLeJ1uK6NjGruFZfc8o
LTW4lVYa8bJYS7cSN8h8s+1LgOGN+jIjtm+3SJUIsUROhYw6AlQgL9+/V087OpAh18EmNVQg7Mc/
R+zvWr9LesGtOxdQXGLYD0tK3Cv6brxzks3sx1DoQZbXqX5t2Okdj4q1uViSukqSKwxW/YDrCPBe
KW4bHAyvj5OJrdu9o54hyokZ7N+1wxrrFv54NkzWbtA+FxyQF2smuvt6L78RHBgOLXMDj6DlNaBa
4kx1HXHhOThTeEDMg5PXCp6dW4+K5OXgSORIskfNTip1KnvyIvbJvgmRlld6iIis7nCs+dwp4wwc
OxJORNanTrAmyPPZGpeRaOrvjUYG0lZFWJo8DA+DuAUlwznPO6Q0ibd5Ei9Hxeepl2n8pndntd97
8XplFeRhVmUCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFIHEjMz15DD/pQwIX4wVZyF0Ad/fMA0GCSqGSIb3DQEBCwUAA4ICAQATZSL1jiutROTL/7lo
5sOASD0Ee/ojL3rtNtqyzm325p7lX1iPyzcyochltq44PTUbPrw7tgTQvPlJ9Zv3hcU2tsu8+Mg5
1eRfB70VVJd0ysrtT7q6ZHafgbiERUlMjW+i67HM0cOU2kTC5uLqGOiiHycFutfl1qnN3e92mI0A
Ds0b+gO3joBYDic/UvuUospeZcnWhNq5NXHzJsBPd+aBJ9J3O5oUb3n09tDh05S60FdRvScFDcH9
yBIw7m+NESsIndTUv4BFFJqIRNow6rSn4+7vW4LVPtateJLbXDzz2K36uGt/xDYotgIVilQsnLAX
c47QN6MUPJiVAAwpBVueSUmxX8fjy88nZY41F7dXyDDZQVu5FLbowg+UMaeUmMxq67XhJ/UQqAHo
jhJi6IjMtX9Gl8CbEGY4GjZGXyJoPd/JxhMnq1MGrKI8hgZlb7F+sSlEmqO6SWkoaY/X5V+tBIZk
bxqgDMUIYs6Ao9Dz7GjevjPHF1t/gMRMTLGmhIrDO7gJzRSBuhjjVFc2/tsvfEehOjPI+Vg7RE+x
ygKJBJYoaMVLuCaJu9YzL1DV/pqJuhgyklTGW+Cd+V7lDSKb9triyCGyYiGqhkCyLmTTX8jjfhFn
RR8F/uOi77Oos/N9j/gMHyIfLXC0uAE0djAA5SN4p1bXUB+K+wb1whnw0A==
-----END CERTIFICATE-----

UCA Extended Validation Root
============================
-----BEGIN CERTIFICATE-----
MIIFWjCCA0KgAwIBAgIQT9Irj/VkyDOeTzRYZiNwYDANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQG
EwJDTjERMA8GA1UECgwIVW5pVHJ1c3QxJTAjBgNVBAMMHFVDQSBFeHRlbmRlZCBWYWxpZGF0aW9u
IFJvb3QwHhcNMTUwMzEzMDAwMDAwWhcNMzgxMjMxMDAwMDAwWjBHMQswCQYDVQQGEwJDTjERMA8G
A1UECgwIVW5pVHJ1c3QxJTAjBgNVBAMMHFVDQSBFeHRlbmRlZCBWYWxpZGF0aW9uIFJvb3QwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCpCQcoEwKwmeBkqh5DFnpzsZGgdT6o+uM4AHrs
iWogD4vFsJszA1qGxliG1cGFu0/GnEBNyr7uaZa4rYEwmnySBesFK5pI0Lh2PpbIILvSsPGP2KxF
Rv+qZ2C0d35qHzwaUnoEPQc8hQ2E0B92CvdqFN9y4zR8V05WAT558aopO2z6+I9tTcg1367r3CTu
eUWnhbYFiN6IXSV8l2RnCdm/WhUFhvMJHuxYMjMR83dksHYf5BA1FxvyDrFspCqjc/wJHx4yGVMR
59mzLC52LqGj3n5qiAno8geK+LLNEOfic0CTuwjRP+H8C5SzJe98ptfRr5//lpr1kXuYC3fUfugH
0mK1lTnj8/FtDw5lhIpjVMWAtuCeS31HJqcBCF3RiJ7XwzJE+oJKCmhUfzhTA8ykADNkUVkLo4KR
el7sFsLzKuZi2irbWWIQJUoqgQtHB0MGcIfS+pMRKXpITeuUx3BNr2fVUbGAIAEBtHoIppB/TuDv
B0GHr2qlXov7z1CymlSvw4m6WC31MJixNnI5fkkE/SmnTHnkBVfblLkWU41Gsx2VYVdWf6/wFlth
WG82UBEL2KwrlRYaDh8IzTY0ZRBiZtWAXxQgXy0MoHgKaNYs1+lvK9JKBZP8nm9rZ/+I8U6laUpS
NwXqxhaN0sSZ0YIrO7o1dfdRUVjzyAfd5LQDfwIDAQABo0IwQDAdBgNVHQ4EFgQU2XQ65DA9DfcS
3H5aBZ8eNJr34RQwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQEL
BQADggIBADaNl8xCFWQpN5smLNb7rhVpLGsaGvdftvkHTFnq88nIua7Mui563MD1sC3AO6+fcAUR
ap8lTwEpcOPlDOHqWnzcSbvBHiqB9RZLcpHIojG5qtr8nR/zXUACE/xOHAbKsxSQVBcZEhrxH9cM
aVr2cXj0lH2RC47skFSOvG+hTKv8dGT9cZr4QQehzZHkPJrgmzI5c6sq1WnIeJEmMX3ixzDx/BR4
dxIOE/TdFpS/S2d7cFOFyrC78zhNLJA5wA3CXWvp4uXViI3WLL+rG761KIcSF3Ru/H38j9CHJrAb
+7lsq+KePRXBOy5nAliRn+/4Qh8st2j1da3Ptfb/EX3C8CSlrdP6oDyp+l3cpaDvRKS+1ujl5BOW
F3sGPjLtx7dCvHaj2GU4Kzg1USEODm8uNBNA4StnDG1KQTAYI1oyVZnJF+A83vbsea0rWBmirSwi
GpWOvpaQXUJXxPkUAzUrHC1RVwinOt4/5Mi0A3PCwSaAuwtCH60NryZy2sy+s6ODWA2CxR9GUeOc
GMyNm43sSet1UNWMKFnKdDTajAshqx7qG+XH/RU+wBeq+yNuJkbL+vmxcmtpzyKEC2IPrNkZAJSi
djzULZrtBJ4tBmIQN1IchXIbJ+XMxjHsN+xjWZsLHXbMfjKaiJUINlK73nZfdklJrX+9ZSCyycEr
dhh2n1ax
-----END CERTIFICATE-----

Certigna Root CA
================
-----BEGIN CERTIFICATE-----
MIIGWzCCBEOgAwIBAgIRAMrpG4nxVQMNo+ZBbcTjpuEwDQYJKoZIhvcNAQELBQAwWjELMAkGA1UE
BhMCRlIxEjAQBgNVBAoMCURoaW15b3RpczEcMBoGA1UECwwTMDAwMiA0ODE0NjMwODEwMDAzNjEZ
MBcGA1UEAwwQQ2VydGlnbmEgUm9vdCBDQTAeFw0xMzEwMDEwODMyMjdaFw0zMzEwMDEwODMyMjda
MFoxCzAJBgNVBAYTAkZSMRIwEAYDVQQKDAlEaGlteW90aXMxHDAaBgNVBAsMEzAwMDIgNDgxNDYz
MDgxMDAwMzYxGTAXBgNVBAMMEENlcnRpZ25hIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQDNGDllGlmx6mQWDoyUJJV8g9PFOSbcDO8WV43X2KyjQn+Cyu3NW9sOty3tRQgX
stmzy9YXUnIo245Onoq2C/mehJpNdt4iKVzSs9IGPjA5qXSjklYcoW9MCiBtnyN6tMbaLOQdLNyz
KNAT8kxOAkmhVECe5uUFoC2EyP+YbNDrihqECB63aCPuI9Vwzm1RaRDuoXrC0SIxwoKF0vJVdlB8
JXrJhFwLrN1CTivngqIkicuQstDuI7pmTLtipPlTWmR7fJj6o0ieD5Wupxj0auwuA0Wv8HT4Ks16
XdG+RCYyKfHx9WzMfgIhC59vpD++nVPiz32pLHxYGpfhPTc3GGYo0kDFUYqMwy3OU4gkWGQwFsWq
4NYKpkDfePb1BHxpE4S80dGnBs8B92jAqFe7OmGtBIyT46388NtEbVncSVmurJqZNjBBe3YzIoej
wpKGbvlw7q6Hh5UbxHq9MfPU0uWZ/75I7HX1eBYdpnDBfzwboZL7z8g81sWTCo/1VTp2lc5ZmIoJ
lXcymoO6LAQ6l73UL77XbJuiyn1tJslV1c/DeVIICZkHJC1kJWumIWmbat10TWuXekG9qxf5kBdI
jzb5LdXF2+6qhUVB+s06RbFo5jZMm5BX7CO5hwjCxAnxl4YqKE3idMDaxIzb3+KhF1nOJFl0Mdp/
/TBt2dzhauH8XwIDAQABo4IBGjCCARYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
HQYDVR0OBBYEFBiHVuBud+4kNTxOc5of1uHieX4rMB8GA1UdIwQYMBaAFBiHVuBud+4kNTxOc5of
1uHieX4rMEQGA1UdIAQ9MDswOQYEVR0gADAxMC8GCCsGAQUFBwIBFiNodHRwczovL3d3d3cuY2Vy
dGlnbmEuZnIvYXV0b3JpdGVzLzBtBgNVHR8EZjBkMC+gLaArhilodHRwOi8vY3JsLmNlcnRpZ25h
LmZyL2NlcnRpZ25hcm9vdGNhLmNybDAxoC+gLYYraHR0cDovL2NybC5kaGlteW90aXMuY29tL2Nl
cnRpZ25hcm9vdGNhLmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlLieT/DjlQgi581oQfccVdV8AOIt
OoldaDgvUSILSo3L6btdPrtcPbEo/uRTVRPPoZAbAh1fZkYJMyjhDSSXcNMQH+pkV5a7XdrnxIxP
TGRGHVyH41neQtGbqH6mid2PHMkwgu07nM3A6RngatgCdTer9zQoKJHyBApPNeNgJgH60BGM+RFq
7q89w1DTj18zeTyGqHNFkIwgtnJzFyO+B2XleJINugHA64wcZr+shncBlA2c5uk5jR+mUYyZDDl3
4bSb+hxnV29qao6pK0xXeXpXIs/NX2NGjVxZOob4Mkdio2cNGJHc+6Zr9UhhcyNZjgKnvETq9Emd
8VRY+WCv2hikLyhF3HqgiIZd8zvn/yk1gPxkQ5Tm4xxvvq0OKmOZK8l+hfZx6AYDlf7ej0gcWtSS
6Cvu5zHbugRqh5jnxV/vfaci9wHYTfmJ0A6aBVmknpjZbyvKcL5kwlWj9Omvw5Ip3IgWJJk8jSaY
tlu3zM63Nwf9JtmYhST/WSMDmu2dnajkXjjO11INb9I/bbEFa0nOipFGc/T2L/Coc3cOZayhjWZS
aX5LaAzHHjcng6WMxwLkFM1JAbBzs/3GkDpv0mztO+7skb6iQ12LAEpmJURw3kAP+HwV96LOPNde
E4yBFxgX0b3xdxA61GU5wSesVywlVP+i2k+KYTlerj1KjL0=
-----END CERTIFICATE-----

emSign Root CA - G1
===================
-----BEGIN CERTIFICATE-----
MIIDlDCCAnygAwIBAgIKMfXkYgxsWO3W2DANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJJTjET
MBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
ZDEcMBoGA1UEAxMTZW1TaWduIFJvb3QgQ0EgLSBHMTAeFw0xODAyMTgxODMwMDBaFw00MzAyMTgx
ODMwMDBaMGcxCzAJBgNVBAYTAklOMRMwEQYDVQQLEwplbVNpZ24gUEtJMSUwIwYDVQQKExxlTXVk
aHJhIFRlY2hub2xvZ2llcyBMaW1pdGVkMRwwGgYDVQQDExNlbVNpZ24gUm9vdCBDQSAtIEcxMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk0u76WaK7p1b1TST0Bsew+eeuGQzf2N4aLTN
LnF115sgxk0pvLZoYIr3IZpWNVrzdr3YzZr/k1ZLpVkGoZM0Kd0WNHVO8oG0x5ZOrRkVUkr+PHB1
cM2vK6sVmjM8qrOLqs1D/fXqcP/tzxE7lM5OMhbTI0Aqd7OvPAEsbO2ZLIvZTmmYsvePQbAyeGHW
DV/D+qJAkh1cF+ZwPjXnorfCYuKrpDhMtTk1b+oDafo6VGiFbdbyL0NVHpENDtjVaqSW0RM8LHhQ
6DqS0hdW5TUaQBw+jSztOd9C4INBdN+jzcKGYEho42kLVACL5HZpIQ15TjQIXhTCzLG3rdd8cIrH
hQIDAQABo0IwQDAdBgNVHQ4EFgQU++8Nhp6w492pufEhF38+/PB3KxowDgYDVR0PAQH/BAQDAgEG
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFn/8oz1h31xPaOfG1vR2vjTnGs2
vZupYeveFix0PZ7mddrXuqe8QhfnPZHr5X3dPpzxz5KsbEjMwiI/aTvFthUvozXGaCocV685743Q
NcMYDHsAVhzNixl03r4PEuDQqqE/AjSxcM6dGNYIAwlG7mDgfrbESQRRfXBgvKqy/3lyeqYdPV8q
+Mri/Tm3R7nrft8EI6/6nAYH6ftjk4BAtcZsCjEozgyfz7MjNYBBjWzEN3uBL4ChQEKF6dk4jeih
U80Bv2noWgbyRQuQ+q7hv53yrlc8pa6yVvSLZUDp/TGBLPQ5Cdjua6e0ph0VpZj3AYHYhX3zUVxx
iN66zB+Afko=
-----END CERTIFICATE-----

emSign ECC Root CA - G3
=======================
-----BEGIN CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQGEwJJTjETMBEG
A1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4
MTgzMDAwWjBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11
ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0WXTsuwYc
58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xySfvalY8L1X44uT6EYGQIr
MgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuBzhccLikenEhjQjAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+D
CBeQyh+KTOgNG3qxrdWBCUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7
jHvrZQnD+JbNR6iC8hZVdyR+EhCVBCyj
-----END CERTIFICATE-----

emSign Root CA - C1
===================
-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgILAK7PALrEzzL4Q7IwDQYJKoZIhvcNAQELBQAwVjELMAkGA1UEBhMCVVMx
EzARBgNVBAsTCmVtU2lnbiBQS0kxFDASBgNVBAoTC2VNdWRocmEgSW5jMRwwGgYDVQQDExNlbVNp
Z24gUm9vdCBDQSAtIEMxMB4XDTE4MDIxODE4MzAwMFoXDTQzMDIxODE4MzAwMFowVjELMAkGA1UE
BhMCVVMxEzARBgNVBAsTCmVtU2lnbiBQS0kxFDASBgNVBAoTC2VNdWRocmEgSW5jMRwwGgYDVQQD
ExNlbVNpZ24gUm9vdCBDQSAtIEMxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+up
ufGZBczYKCFK83M0UYRWEPWgTywS4/oTmifQz/l5GnRfHXk5/Fv4cI7gklL35CX5VIPZHdPIWoU/
Xse2B+4+wM6ar6xWQio5JXDWv7V7Nq2s9nPczdcdioOl+yuQFTdrHCZH3DspVpNqs8FqOp099cGX
OFgFixwR4+S0uF2FHYP+eF8LRWgYSKVGczQ7/g/IdrvHGPMF0Ybzhe3nudkyrVWIzqa2kbBPrH4V
I5b2P/AgNBbeCsbEBEV5f6f9vtKppa+cxSMq9zwhbL2vj07FOrLzNBL834AaSaTUqZX3noleooms
lMuoaJuvimUnzYnu3Yy1aylwQ6BpC+S5DwIDAQABo0IwQDAdBgNVHQ4EFgQU/qHgcB4qAzlSWkK+
XJGFehiqTbUwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD
ggEBAMJKVvoVIXsoounlHfv4LcQ5lkFMOycsxGwYFYDGrK9HWS8mC+M2sO87/kOXSTKZEhVb3xEp
/6tT+LvBeA+snFOvV71ojD1pM/CjoCNjO2RnIkSt1XHLVip4kqNPEjE2NuLe/gDEo2APJ62gsIq1
NnpSob0n9CAnYuhNlCQT5AoE6TyrLshDCUrGYQTlSTR+08TI9Q/Aqum6VF7zYytPT1DU/rl7mYw9
wC68AivTxEDkigcxHpvOJpkT+xHqmiIMERnHXhuBUDDIlhJu58tBf5E7oke3VIAb3ADMmpDqw8NQ
BmIMMMAVSKeoWXzhriKi4gp6D/piq1JM4fHfyr6DDUI=
-----END CERTIFICATE-----

emSign ECC Root CA - C3
=======================
-----BEGIN CERTIFICATE-----
MIICKzCCAbGgAwIBAgIKe3G2gla4EnycqDAKBggqhkjOPQQDAzBaMQswCQYDVQQGEwJVUzETMBEG
A1UECxMKZW1TaWduIFBLSTEUMBIGA1UEChMLZU11ZGhyYSBJbmMxIDAeBgNVBAMTF2VtU2lnbiBF
Q0MgUm9vdCBDQSAtIEMzMB4XDTE4MDIxODE4MzAwMFoXDTQzMDIxODE4MzAwMFowWjELMAkGA1UE
BhMCVVMxEzARBgNVBAsTCmVtU2lnbiBQS0kxFDASBgNVBAoTC2VNdWRocmEgSW5jMSAwHgYDVQQD
ExdlbVNpZ24gRUNDIFJvb3QgQ0EgLSBDMzB2MBAGByqGSM49AgEGBSuBBAAiA2IABP2lYa57JhAd
6bciMK4G9IGzsUJxlTm801Ljr6/58pc1kjZGDoeVjbk5Wum739D+yAdBPLtVb4OjavtisIGJAnB9
SMVK4+kiVCJNk7tCDK93nCOmfddhEc5lx/h//vXyqaNCMEAwHQYDVR0OBBYEFPtaSNCAIEDyqOkA
B2kZd6fmw/TPMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMDA2gA
MGUCMQC02C8Cif22TGK6Q04ThHK1rt0c3ta13FaPWEBaLd4gTCKDypOofu4SQMfWh0/434UCMBwU
ZOR8loMRnLDRWmFLpg9J0wD8ofzkpf9/rdcw0Md3f76BB1UwUCAU9Vc4CqgxUQ==
-----END CERTIFICATE-----

Hongkong Post Root CA 3
=======================
-----BEGIN CERTIFICATE-----
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
dBb9HxEGmpv0
-----END CERTIFICATE-----

Entrust Root Certification Authority - G4
=========================================
-----BEGIN CERTIFICATE-----
MIIGSzCCBDOgAwIBAgIRANm1Q3+vqTkPAAAAAFVlrVgwDQYJKoZIhvcNAQELBQAwgb4xCzAJBgNV
BAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQLEx9TZWUgd3d3LmVudHJ1c3Qu
bmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykgMjAxNSBFbnRydXN0LCBJbmMuIC0gZm9yIGF1
dGhvcml6ZWQgdXNlIG9ubHkxMjAwBgNVBAMTKUVudHJ1c3QgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eSAtIEc0MB4XDTE1MDUyNzExMTExNloXDTM3MTIyNzExNDExNlowgb4xCzAJBgNVBAYT
AlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQLEx9TZWUgd3d3LmVudHJ1c3QubmV0
L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykgMjAxNSBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhv
cml6ZWQgdXNlIG9ubHkxMjAwBgNVBAMTKUVudHJ1c3QgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhv
cml0eSAtIEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsewsQu7i0TD/pZJH4i3D
umSXbcr3DbVZwbPLqGgZ2K+EbTBwXX7zLtJTmeH+H17ZSK9dE43b/2MzTdMAArzE+NEGCJR5WIoV
3imz/f3ET+iq4qA7ec2/a0My3dl0ELn39GjUu9CH1apLiipvKgS1sqbHoHrmSKvS0VnM1n4j5pds
8ELl3FFLFUHtSUrJ3hCX1nbB76W1NhSXNdh4IjVS70O92yfbYVaCNNzLiGAMC1rlLAHGVK/XqsEQ
e9IFWrhAnoanw5CGAlZSCXqc0ieCU0plUmr1POeo8pyvi73TDtTUXm6Hnmo9RR3RXRv06QqsYJn7
ibT/mCzPfB3pAqoEmh643IhuJbNsZvc8kPNXwbMv9W3y+8qh+CmdRouzavbmZwe+LGcKKh9asj5X
xNMhIWNlUpEbsZmOeX7m640A2Vqq6nPopIICR5b+W45UYaPrL0swsIsjdXJ8ITzI9vF01Bx7owVV
7rtNOzK+mndmnqxpkCIHH2E6lr7lmk/MBTwoWdPBDFSoWWG9yHJM6Nyfh3+9nEg2XpWjDrk4JFX8
dWbrAuMINClKxuMrLzOg2qOGpRKX/YAr2hRC45K9PvJdXmd0LhyIRyk0X+IyqJwlN4y6mACXi0mW
Hv0liqzc2thddG5msP9E36EYxr5ILzeUePiVSj9/E15dWf10hkNjc0kCAwEAAaNCMEAwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJ84xFYjwznooHFs6FRM5Og6sb9n
MA0GCSqGSIb3DQEBCwUAA4ICAQAS5UKme4sPDORGpbZgQIeMJX6tuGguW8ZAdjwD+MlZ9POrYs4Q
jbRaZIxowLByQzTSGwv2LFPSypBLhmb8qoMi9IsabyZIrHZ3CL/FmFz0Jomee8O5ZDIBf9PD3Vht
7LGrhFV0d4QEJ1JrhkzO3bll/9bGXp+aEJlLdWr+aumXIOTkdnrG0CSqkM0gkLpHZPt/B7NTeLUK
YvJzQ85BK4FqLoUWlFPUa19yIqtRLULVAJyZv967lDtX/Zr1hstWO1uIAeV8KEsD+UmDfLJ/fOPt
jqF/YFOOVZ1QNBIPt5d7bIdKROf1beyAN/BYGW5KaHbwH5Lk6rWS02FREAutp9lfx1/cH6NcjKF+
m7ee01ZvZl4HliDtC3T7Zk6LERXpgUl+b7DUUH8i119lAg2m9IUe2K4GS0qn0jFmwvjO5QimpAKW
RGhXxNUzzxkvFMSUHHuk2fCfDrGA4tGeEWSpiBE6doLlYsKA2KSD7ZPvfC+QsDJMlhVoSFLUmQjA
JOgc47OlIQ6SwJAfzyBfyjs4x7dtOvPmRLgOMWuIjnDrnBdSqEGULoe256YSxXXfW8AKbnuk5F6G
+TaU33fD6Q3AOfF5u0aOq0NZJ7cguyPpVkAh7DE9ZapD8j3fcEThuk0mEDuYn/PIjhs4ViFqUZPT
kcpG2om3PVODLAgfi49T3f+sHw==
-----END CERTIFICATE-----

Microsoft ECC Root Certificate Authority 2017
=============================================
-----BEGIN CERTIFICATE-----
MIICWTCCAd+gAwIBAgIQZvI9r4fei7FK6gxXMQHC7DAKBggqhkjOPQQDAzBlMQswCQYDVQQGEwJV
UzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTYwNAYDVQQDEy1NaWNyb3NvZnQgRUND
IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTcwHhcNMTkxMjE4MjMwNjQ1WhcNNDIwNzE4
MjMxNjA0WjBlMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTYw
NAYDVQQDEy1NaWNyb3NvZnQgRUNDIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTcwdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAATUvD0CQnVBEyPNgASGAlEvaqiBYgtlzPbKnR5vSmZRogPZnZH6
thaxjG7efM3beaYvzrvOcS/lpaso7GMEZpn4+vKTEAXhgShC48Zo9OYbhGBKia/teQ87zvH2RPUB
eMCjVDBSMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIy5lycFIM
+Oa+sgRXKSrPQhDtNTAQBgkrBgEEAYI3FQEEAwIBADAKBggqhkjOPQQDAwNoADBlAjBY8k3qDPlf
Xu5gKcs68tvWMoQZP3zVL8KxzJOuULsJMsbG7X7JNpQS5GiFBqIb0C8CMQCZ6Ra0DvpWSNSkMBaR
eNtUjGUBiudQZsIxtzm6uBoiB078a1QWIP8rtedMDE2mT3M=
-----END CERTIFICATE-----

Microsoft RSA Root Certificate Authority 2017
=============================================
-----BEGIN CERTIFICATE-----
MIIFqDCCA5CgAwIBAgIQHtOXCV/YtLNHcB6qvn9FszANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQG
EwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTYwNAYDVQQDEy1NaWNyb3NvZnQg
UlNBIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTcwHhcNMTkxMjE4MjI1MTIyWhcNNDIw
NzE4MjMwMDIzWjBlMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
MTYwNAYDVQQDEy1NaWNyb3NvZnQgUlNBIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTcw
ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDKW76UM4wplZEWCpW9R2LBifOZNt9GkMml
7Xhqb0eRaPgnZ1AzHaGm++DlQ6OEAlcBXZxIQIJTELy/xztokLaCLeX0ZdDMbRnMlfl7rEqUrQ7e
S0MdhweSE5CAg2Q1OQT85elss7YfUJQ4ZVBcF0a5toW1HLUX6NZFndiyJrDKxHBKrmCk3bPZ7Pw7
1VdyvD/IybLeS2v4I2wDwAW9lcfNcztmgGTjGqwu+UcF8ga2m3P1eDNbx6H7JyqhtJqRjJHTOoI+
dkC0zVJhUXAoP8XFWvLJjEm7FFtNyP9nTUwSlq31/niol4fX/V4ggNyhSyL71Imtus5Hl0dVe49F
yGcohJUcaDDv70ngNXtk55iwlNpNhTs+VcQor1fznhPbRiefHqJeRIOkpcrVE7NLP8TjwuaGYaRS
MLl6IE9vDzhTyzMMEyuP1pq9KsgtsRx9S1HKR9FIJ3Jdh+vVReZIZZ2vUpC6W6IYZVcSn2i51BVr
lMRpIpj0M+Dt+VGOQVDJNE92kKz8OMHY4Xu54+OU4UZpyw4KUGsTuqwPN1q3ErWQgR5WrlcihtnJ
0tHXUeOrO8ZV/R4O03QK0dqq6mm4lyiPSMQH+FJDOvTKVTUssKZqwJz58oHhEmrARdlns87/I6KJ
ClTUFLkqqNfs+avNJVgyeY+QW5g5xAgGwax/Dj0ApQIDAQABo1QwUjAOBgNVHQ8BAf8EBAMCAYYw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUCctZf4aycI8awznjwNnpv7tNsiMwEAYJKwYBBAGC
NxUBBAMCAQAwDQYJKoZIhvcNAQEMBQADggIBAKyvPl3CEZaJjqPnktaXFbgToqZCLgLNFgVZJ8og
6Lq46BrsTaiXVq5lQ7GPAJtSzVXNUzltYkyLDVt8LkS/gxCP81OCgMNPOsduET/m4xaRhPtthH80
dK2Jp86519efhGSSvpWhrQlTM93uCupKUY5vVau6tZRGrox/2KJQJWVggEbbMwSubLWYdFQl3JPk
+ONVFT24bcMKpBLBaYVu32TxU5nhSnUgnZUP5NbcA/FZGOhHibJXWpS2qdgXKxdJ5XbLwVaZOjex
/2kskZGT4d9Mozd2TaGf+G0eHdP67Pv0RR0Tbc/3WeUiJ3IrhvNXuzDtJE3cfVa7o7P4NHmJweDy
AmH3pvwPuxwXC65B2Xy9J6P9LjrRk5Sxcx0ki69bIImtt2dmefU6xqaWM/5TkshGsRGRxpl/j8nW
ZjEgQRCHLQzWwa80mMpkg/sTV9HB8Dx6jKXB/ZUhoHHBk2dxEuqPiAppGWSZI1b7rCoucL5mxAyE
7+WL85MB+GqQk2dLsmijtWKP6T+MejteD+eMuMZ87zf9dOLITzNy4ZQ5bb0Sr74MTnB8G2+NszKT
c0QWbej09+CVgI+WXTik9KveCjCHk9hNAHFiRSdLOkKEW39lt2c0Ui2cFmuqqNh7o0JMcccMyj6D
5KbvtwEwXlGjefVwaaZBRA+GsCyRxj3qrg+E
-----END CERTIFICATE-----

e-Szigno Root CA 2017
=====================
-----BEGIN CERTIFICATE-----
MIICQDCCAeWgAwIBAgIMAVRI7yH9l1kN9QQKMAoGCCqGSM49BAMCMHExCzAJBgNVBAYTAkhVMREw
DwYDVQQHDAhCdWRhcGVzdDEWMBQGA1UECgwNTWljcm9zZWMgTHRkLjEXMBUGA1UEYQwOVkFUSFUt
MjM1ODQ0OTcxHjAcBgNVBAMMFWUtU3ppZ25vIFJvb3QgQ0EgMjAxNzAeFw0xNzA4MjIxMjA3MDZa
Fw00MjA4MjIxMjA3MDZaMHExCzAJBgNVBAYTAkhVMREwDwYDVQQHDAhCdWRhcGVzdDEWMBQGA1UE
CgwNTWljcm9zZWMgTHRkLjEXMBUGA1UEYQwOVkFUSFUtMjM1ODQ0OTcxHjAcBgNVBAMMFWUtU3pp
Z25vIFJvb3QgQ0EgMjAxNzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJbcPYrYsHtvxie+RJCx
s1YVe45DJH0ahFnuY2iyxl6H0BVIHqiQrb1TotreOpCmYF9oMrWGQd+HWyx7xf58etqjYzBhMA8G
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSHERUI0arBeAyxr87GyZDv
vzAEwDAfBgNVHSMEGDAWgBSHERUI0arBeAyxr87GyZDvvzAEwDAKBggqhkjOPQQDAgNJADBGAiEA
tVfd14pVCzbhhkT61NlojbjcI4qKDdQvfepz7L9NbKgCIQDLpbQS+ue16M9+k/zzNY9vTlp8tLxO
svxyqltZ+efcMQ==
-----END CERTIFICATE-----

certSIGN Root CA G2
===================
-----BEGIN CERTIFICATE-----
MIIFRzCCAy+gAwIBAgIJEQA0tk7GNi02MA0GCSqGSIb3DQEBCwUAMEExCzAJBgNVBAYTAlJPMRQw
EgYDVQQKEwtDRVJUU0lHTiBTQTEcMBoGA1UECxMTY2VydFNJR04gUk9PVCBDQSBHMjAeFw0xNzAy
MDYwOTI3MzVaFw00MjAyMDYwOTI3MzVaMEExCzAJBgNVBAYTAlJPMRQwEgYDVQQKEwtDRVJUU0lH
TiBTQTEcMBoGA1UECxMTY2VydFNJR04gUk9PVCBDQSBHMjCCAiIwDQYJKoZIhvcNAQEBBQADggIP
ADCCAgoCggIBAMDFdRmRfUR0dIf+DjuW3NgBFszuY5HnC2/OOwppGnzC46+CjobXXo9X69MhWf05
N0IwvlDqtg+piNguLWkh59E3GE59kdUWX2tbAMI5Qw02hVK5U2UPHULlj88F0+7cDBrZuIt4Imfk
abBoxTzkbFpG583H+u/E7Eu9aqSs/cwoUe+StCmrqzWaTOTECMYmzPhpn+Sc8CnTXPnGFiWeI8Mg
wT0PPzhAsP6CRDiqWhqKa2NYOLQV07YRaXseVO6MGiKscpc/I1mbySKEwQdPzH/iV8oScLumZfNp
dWO9lfsbl83kqK/20U6o2YpxJM02PbyWxPFsqa7lzw1uKA2wDrXKUXt4FMMgL3/7FFXhEZn91Qqh
ngLjYl/rNUssuHLoPj1PrCy7Lobio3aP5ZMqz6WryFyNSwb/EkaseMsUBzXgqd+L6a8VTxaJW732
jcZZroiFDsGJ6x9nxUWO/203Nit4ZoORUSs9/1F3dmKh7Gc+PoGD4FapUB8fepmrY7+EF3fxDTvf
95xhszWYijqy7DwaNz9+j5LP2RIUZNoQAhVB/0/E6xyjyfqZ90bp4RjZsbgyLcsUDFDYg2WD7rlc
z8sFWkz6GZdr1l0T08JcVLwyc6B49fFtHsufpaafItzRUZ6CeWRgKRM+o/1Pcmqr4tTluCRVLERL
iohEnMqE0yo7AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1Ud
DgQWBBSCIS1mxteg4BXrzkwJd8RgnlRuAzANBgkqhkiG9w0BAQsFAAOCAgEAYN4auOfyYILVAzOB
ywaK8SJJ6ejqkX/GM15oGQOGO0MBzwdw5AgeZYWR5hEit/UCI46uuR59H35s5r0l1ZUa8gWmr4UC
b6741jH/JclKyMeKqdmfS0mbEVeZkkMR3rYzpMzXjWR91M08KCy0mpbqTfXERMQlqiCA2ClV9+BB
/AYm/7k29UMUA2Z44RGx2iBfRgB4ACGlHgAoYXhvqAEBj500mv/0OJD7uNGzcgbJceaBxXntC6Z5
8hMLnPddDnskk7RI24Zf3lCGeOdA5jGokHZwYa+cNywRtYK3qq4kNFtyDGkNzVmf9nGvnAvRCjj5
BiKDUyUM/FHE5r7iOZULJK2v0ZXkltd0ZGtxTgI8qoXzIKNDOXZbbFD+mpwUHmUUihW9o4JFWklW
atKcsWMy5WHgUyIOpwpJ6st+H6jiYoD2EEVSmAYY3qXNL3+q1Ok+CHLsIwMCPKaq2LxndD0UF/tU
Sxfj03k9bWtJySgOLnRQvwzZRjoQhsmnP+mg7H/rpXdYaXHmgwo38oZJar55CJD2AhZkPuXaTH4M
NMn5X7azKFGnpyuqSfqNZSlO42sTp5SjLVFteAxEy9/eCG/Oo2Sr05WE1LlSVHJ7liXMvGnjSG4N
0MedJ5qq+BOS3R7fY581qRY27Iy4g/Q9iY/NtBde17MXQRBdJ3NghVdJIgc=
-----END CERTIFICATE-----

Trustwave Global Certification Authority
========================================
-----BEGIN CERTIFICATE-----
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
29FpHOTKyeC2nOnOcXHebD8WpHk=
-----END CERTIFICATE-----

Trustwave Global ECC P256 Certification Authority
=================================================
-----BEGIN CERTIFICATE-----
MIICYDCCAgegAwIBAgIMDWpfCD8oXD5Rld9dMAoGCCqGSM49BAMCMIGRMQswCQYDVQQGEwJVUzER
MA8GA1UECBMISWxsaW5vaXMxEDAOBgNVBAcTB0NoaWNhZ28xITAfBgNVBAoTGFRydXN0d2F2ZSBI
b2xkaW5ncywgSW5jLjE6MDgGA1UEAxMxVHJ1c3R3YXZlIEdsb2JhbCBFQ0MgUDI1NiBDZXJ0aWZp
Y2F0aW9uIEF1dGhvcml0eTAeFw0xNzA4MjMxOTM1MTBaFw00MjA4MjMxOTM1MTBaMIGRMQswCQYD
VQQGEwJVUzERMA8GA1UECBMISWxsaW5vaXMxEDAOBgNVBAcTB0NoaWNhZ28xITAfBgNVBAoTGFRy
dXN0d2F2ZSBIb2xkaW5ncywgSW5jLjE6MDgGA1UEAxMxVHJ1c3R3YXZlIEdsb2JhbCBFQ0MgUDI1
NiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH77bOYj
43MyCMpg5lOcunSNGLB4kFKA3TjASh3RqMyTpJcGOMoNFWLGjgEqZZ2q3zSRLoHB5DOSMcT9CTqm
P62jQzBBMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0PAQH/BAUDAwcGADAdBgNVHQ4EFgQUo0EGrJBt
0UrrdaVKEJmzsaGLSvcwCgYIKoZIzj0EAwIDRwAwRAIgB+ZU2g6gWrKuEZ+Hxbb/ad4lvvigtwjz
RM4q3wghDDcCIC0mA6AFvWvR9lz4ZcyGbbOcNEhjhAnFjXca4syc4XR7
-----END CERTIFICATE-----

Trustwave Global ECC P384 Certification Authority
=================================================
-----BEGIN CERTIFICATE-----
MIICnTCCAiSgAwIBAgIMCL2Fl2yZJ6SAaEc7MAoGCCqGSM49BAMDMIGRMQswCQYDVQQGEwJVUzER
MA8GA1UECBMISWxsaW5vaXMxEDAOBgNVBAcTB0NoaWNhZ28xITAfBgNVBAoTGFRydXN0d2F2ZSBI
b2xkaW5ncywgSW5jLjE6MDgGA1UEAxMxVHJ1c3R3YXZlIEdsb2JhbCBFQ0MgUDM4NCBDZXJ0aWZp
Y2F0aW9uIEF1dGhvcml0eTAeFw0xNzA4MjMxOTM2NDNaFw00MjA4MjMxOTM2NDNaMIGRMQswCQYD
VQQGEwJVUzERMA8GA1UECBMISWxsaW5vaXMxEDAOBgNVBAcTB0NoaWNhZ28xITAfBgNVBAoTGFRy
dXN0d2F2ZSBIb2xkaW5ncywgSW5jLjE6MDgGA1UEAxMxVHJ1c3R3YXZlIEdsb2JhbCBFQ0MgUDM4
NCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTB2MBAGByqGSM49AgEGBSuBBAAiA2IABGvaDXU1CDFH
Ba5FmVXxERMuSvgQMSOjfoPTfygIOiYaOs+Xgh+AtycJj9GOMMQKmw6sWASr9zZ9lCOkmwqKi6vr
/TklZvFe/oyujUF5nQlgziip04pt89ZF1PKYhDhloKNDMEEwDwYDVR0TAQH/BAUwAwEB/zAPBgNV
HQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBRVqYSJ0sEyvRjLbKYHTsjnnb6CkDAKBggqhkjOPQQDAwNn
ADBkAjA3AZKXRRJ+oPM+rRk6ct30UJMDEr5E0k9BpIycnR+j9sKS50gU/k6bpZFXrsY3crsCMGcl
CrEMXu6pY5Jv5ZAL/mYiykf9ijH3g/56vxC+GCsej/YpHpRZ744hN8tRmKVuSw==
-----END CERTIFICATE-----

NAVER Global Root Certification Authority
=========================================
-----BEGIN CERTIFICATE-----
MIIFojCCA4qgAwIBAgIUAZQwHqIL3fXFMyqxQ0Rx+NZQTQ0wDQYJKoZIhvcNAQEMBQAwaTELMAkG
A1UEBhMCS1IxJjAkBgNVBAoMHU5BVkVSIEJVU0lORVNTIFBMQVRGT1JNIENvcnAuMTIwMAYDVQQD
DClOQVZFUiBHbG9iYWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNzA4MTgwODU4
NDJaFw0zNzA4MTgyMzU5NTlaMGkxCzAJBgNVBAYTAktSMSYwJAYDVQQKDB1OQVZFUiBCVVNJTkVT
UyBQTEFURk9STSBDb3JwLjEyMDAGA1UEAwwpTkFWRVIgR2xvYmFsIFJvb3QgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC21PGTXLVAiQqrDZBb
UGOukJR0F0Vy1ntlWilLp1agS7gvQnXp2XskWjFlqxcX0TM62RHcQDaH38dq6SZeWYp34+hInDEW
+j6RscrJo+KfziFTowI2MMtSAuXaMl3Dxeb57hHHi8lEHoSTGEq0n+USZGnQJoViAbbJAh2+g1G7
XNr4rRVqmfeSVPc0W+m/6imBEtRTkZazkVrd/pBzKPswRrXKCAfHcXLJZtM0l/aM9BhK4dA9WkW2
aacp+yPOiNgSnABIqKYPszuSjXEOdMWLyEz59JuOuDxp7W87UC9Y7cSw0BwbagzivESq2M0UXZR4
Yb8ObtoqvC8MC3GmsxY/nOb5zJ9TNeIDoKAYv7vxvvTWjIcNQvcGufFt7QSUqP620wbGQGHfnZ3z
VHbOUzoBppJB7ASjjw2i1QnK1sua8e9DXcCrpUHPXFNwcMmIpi3Ua2FzUCaGYQ5fG8Ir4ozVu53B
A0K6lNpfqbDKzE0K70dpAy8i+/Eozr9dUGWokG2zdLAIx6yo0es+nPxdGoMuK8u180SdOqcXYZai
cdNwlhVNt0xz7hlcxVs+Qf6sdWA7G2POAN3aCJBitOUt7kinaxeZVL6HSuOpXgRM6xBtVNbv8ejy
YhbLgGvtPe31HzClrkvJE+2KAQHJuFFYwGY6sWZLxNUxAmLpdIQM201GLQIDAQABo0IwQDAdBgNV
HQ4EFgQU0p+I36HNLL3s9TsBAZMzJ7LrYEswDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMB
Af8wDQYJKoZIhvcNAQEMBQADggIBADLKgLOdPVQG3dLSLvCkASELZ0jKbY7gyKoNqo0hV4/GPnrK
21HUUrPUloSlWGB/5QuOH/XcChWB5Tu2tyIvCZwTFrFsDDUIbatjcu3cvuzHV+YwIHHW1xDBE1UB
jCpD5EHxzzp6U5LOogMFDTjfArsQLtk70pt6wKGm+LUx5vR1yblTmXVHIloUFcd4G7ad6Qz4G3bx
hYTeodoS76TiEJd6eN4MUZeoIUCLhr0N8F5OSza7OyAfikJW4Qsav3vQIkMsRIz75Sq0bBwcupTg
E34h5prCy8VCZLQelHsIJchxzIdFV4XTnyliIoNRlwAYl3dqmJLJfGBs32x9SuRwTMKeuB330DTH
D8z7p/8Dvq1wkNoL3chtl1+afwkyQf3NosxabUzyqkn+Zvjp2DXrDige7kgvOtB5CTh8piKCk5XQ
A76+AqAF3SAi428diDRgxuYKuQl1C/AH6GmWNcf7I4GOODm4RStDeKLRLBT/DShycpWbXgnbiUSY
qqFJu3FS8r/2/yehNq+4tneI3TqkbZs0kNwUXTC/t+sX5Ie3cdCh13cV1ELX8vMxmV2b3RZtP+oG
I/hGoiLtk/bdmuYqh7GYVPEi92tF4+KOdh2ajcQGjTa3FPOdVGm3jjzVpG2Tgbet9r1ke8LJaDmg
kpzNNIaRkPpkUZ3+/uul9XXeifdy
-----END CERTIFICATE-----

BEGIN CUSTOM ADDITIONAL CERTS
=============================
-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIICxjCCAk2gAwIBAgIRALO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzEL
MAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo
IEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcN
MjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j
cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c
S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj
+240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd0xhajggEIMIIB
BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V
yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB
BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E
IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG
Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+
Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q
YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAIp5IlCr5SxSbO7Pf8lC3WIwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCzKNx3KdPnkb7ztwoAx/vyVQslImNTNq/pCCDfDa8oPs3Gq1e2naQlGaXS
Mm1Jpgi5xy+hm5PFIEBrhDEgoo4wYCVg79kaiT8faXGy2uo/c0HEkG9m/X2eWNh3
z81ZdUTJoQp7nz8bDjpmb7Z1z4vLr53AcMX/0oIKr13N4uichZSk5gA16H5OOYHH
IYlgd+odlvKLg3tHxG0ywFJ+Ix5FtXHuo+8XwgOpk4nd9Z/buvHa4H6Xh3GBHhqC
VuQ+fBiiCOUWX6j6qOBIUU0YFKAMo+W2yrO1VRJrcsdafzuM+efZ0Y4STTMzAyrx
E+FCPMIuWWAubeAHRzNl39Jnyk2FAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFDadPuCxQPYnLHy/jZ0xivZUpkYmMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCJbu5CalWO+H+Az0lmIG14DXmlYHQE
k26umjuCyioWs2icOlZznPTcZvbfq02YPHGTCu3ctggVDULJ+fwOxKekzIqeyLNk
p8dyFwSAr23DYBIVeXDpxHhShvv0MLJzqqDFBTHYe1X5X2Y7oogy+UDJxV2N24/g
Z8lxG4Vr2/VEfUOrw4Tosl5Z+1uzOdvTyBcxD/E5rGgTLczmulctHy3IMTmdTFr0
FnU0/HMQoquWQuODhFqzMqNcsdbjANUBwOEQrKI8Sy6+b84kHP7PtO+S4Ik8R2k7
ZeMlE1JmxBi/PZU860YlwT8/qOYToCHVyDjhv8qutbf2QnUl3SV86th2I1QQE14s
0y7CdAHcHkw3sAEeYGkwCA74MO+VFtnYbf9B2JBOhyyWb5087rGzitu5MTAW41X9
DwTeXEg+a24tAeht+Y1MionHUwa4j7FB/trN3Fnb/r90+4P66ZETVIEcjseUSMHO
w6yqv10/H/dw/8r2EDUincBBX3o9DL3SadqragkKy96HtMiLcqMMGAPm0gti1b6f
bnvOdr0mrIVIKX5nzOeGZORaYLoSD4C8qvFT7U+Um6DMo36cVDNsPmkF575/s3C2
CxGiCPQqVxPgfNSh+2CPd2Xv04lNeuw6gG89DlOhHuoFKRlmPnom+gwqhz3ZXMfz
TfmvjrBokzCICA==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIICxjCCAkygAwIBAgIQTtI99q9+x/mwxHJv+VEqdzAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw0y
NTA5MTUxNjAwMDBaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABCOaLO3lixmN
YVWex+ZVYOiTLgi0SgNWtU4hufk50VU4Zp/LbBVDxCsnsI7vuf4xp4Cu+ETNggGE
yBqJ3j8iUwe5Yt/qfSrRf1/D5R58duaJ+IvLRXeASRqEL+VkDXrW3qOCAQgwggEE
MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUbZkq9U0C6+MRwWC6km+NPS7x
6kQwHwYDVR0jBBgwFoAUfEKWrt5LSDv6kviejM9ti6lyN5UwMgYIKwYBBQUHAQEE
JjAkMCIGCCsGAQUFBzAChhZodHRwOi8veDIuaS5sZW5jci5vcmcvMCcGA1UdHwQg
MB4wHKAaoBiGFmh0dHA6Ly94Mi5jLmxlbmNyLm9yZy8wIgYDVR0gBBswGTAIBgZn
gQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZIzj0EAwMDaAAwZQIxAPJCN9qpyDmZ
tX8K3m8UYQvK51BrXclM6WfrdeZlUBKyhTXUmFAtJw4X6A0x9mQFPAIwJa/No+KQ
UAM1u34E36neL/Zba7ombkIOchSgx1iVxzqtFWGddgoG+tppRPWhuhhn
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEtjCCAp6gAwIBAgIRAOkSyQ2QhgQ/FnCA3JZEiqgwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwNjA5MTMwNDEx
WhcNMjUwNjEwMTMwNDExWjBUMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxGjAYBgNVBAMTEUlTUkcgUm9vdCBP
Q1NQIFgxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuw0cR9Li4+M+
aIJixENnV4PM9N8nAxwWsM/7PzV/766q/1PKA8jB4OykscNkK9XCblOElSzXSQJx
BrpckIquoydslakPvaB4HLj3cx8EJP4tEyXRDt415uZs9LWFSoplSLBFNC2gMfL7
WYxPqcoOagU+amCVSEDK85oILqnZ27FJrU2hQGOF/lWDa1y1YiIp9e2+ryFOUn1w
AVWQdnOyovh6suBnjCcR+269q6Xtf3/fUHjqnOgO7e8XMDy69MygLltOzDxI0/VA
21EL1kBoC2ckgorVASrKByaPS9o6p2bYcHZ3FC/3g+tv6pCiFZt+e4YMBnYVyAYC
miJVv7PFtQIDAQABo4GHMIGEMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
MB0GA1UdDgQWBBQfuyfyJnprzPH1dNmWK34Z7MMcIzATBgNVHSUEDDAKBggrBgEF
BQcDCTAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAPBgkrBgEFBQcw
AQUEAgUAMA0GCSqGSIb3DQEBCwUAA4ICAQCC1SyXg+js3mvzBv6gHkZBOTP2MPh6
EgQMnWAy2Olu933RBfucYKb4H8JFV7OZQDxa/VJUeVjBwOfQf2Sj7nQp5Aq3m7ug
F228lkLaKOn4c7sX00Px3DpFUpYKHbdGsR69doWRp3mtFuBi3/uAwv1lrvPayzRm
LLtu047CGfD0zmCY/VpuehYZa/g4MLwp6i7Lscvh3B+Jl+daqTYWCNulw8q5gfsE
UXRQzGu5KnBOb6Jw0nrlk7h2YY8N4iP5sBThzl0qRLfy82n4tvs/2IwQd9RBcv6H
+df/sGmjnLvlhAjqjybUQoA/rhkF8PzqKJtpOkaj2qO5XIVJg642T+Kb2qQhohAK
l0YyMxazkQ9qFDuRrljixOIC4iBN40uk5uABF+Vf6UsITJCxkDNakDqKz/nwe+TM
bHXTLuJ1PA+q+Ai73MR9zFW19MffOSaJOR4I/3WeNfUv0nNgYFN8VP60Bjgf7cFc
j+t/zR1pRE/13dguo7FS5EA/52axalq6E+j3/uO7L33+CSBvON0GZlekRcPgvRgq
h0VMhrl6ine7mG0UVBuIg9CLAf+cHCVsDyUiO8x50e5CNEjxh1hxgo46szLU5tHP
aocuXuOLVuLdUat+j/2satKSUStQRigSXAp8fAd5oUXQhSh7GVtIf5eEvGvl04Np
u70vXLDE2hdzTg==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgITBmyf0pY1hp8KD+WGePhbJruKNzANBgkqhkiG9w0BAQwF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAyMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK2Wny2cSkxK
gXlRmeyKy2tgURO8TW0G/LAIjd0ZEGrHJgw12MBvIITplLGbhQPDW9tK6Mj4kHbZ
W0/jTOgGNk3Mmqw9DJArktQGGWCsN0R5hYGCrVo34A3MnaZMUnbqQ523BNFQ9lXg
1dKmSYXpN+nKfq5clU1Imj+uIFptiJXZNLhSGkOQsL9sBbm2eLfq0OQ6PBJTYv9K
8nu+NQWpEjTj82R0Yiw9AElaKP4yRLuH3WUnAnE72kr3H9rN9yFVkE8P7K6C4Z9r
2UXTu/Bfh+08LDmG2j/e7HJV63mjrdvdfLC6HM783k81ds8P+HgfajZRRidhW+me
z/CiVX18JYpvL7TFz4QuK/0NURBs+18bvBt+xa47mAExkv8LV/SasrlX6avvDXbR
8O70zoan4G7ptGmh32n2M8ZpLpcTnqWHsFcQgTfJU7O7f/aS0ZzQGPSSbtqDT6Zj
mUyl+17vIWR6IF9sZIUVyzfpYgwLKhbcAS4y2j5L9Z469hdAlO+ekQiG+r5jqFoz
7Mt0Q5X5bGlSNscpb/xVA1wf+5+9R+vnSUeVC06JIglJ4PVhHvG/LopyboBZ/1c6
+XUyo05f7O0oYtlNc/LMgRdg7c3r3NunysV+Ar3yVAhU/bQtCSwXVEqY0VThUWcI
0u1ufm8/0i2BWSlmy5A5lREedCf+3euvAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSwDPBMMPQFWAJI/TPlUq9LhONm
UjANBgkqhkiG9w0BAQwFAAOCAgEAqqiAjw54o+Ci1M3m9Zh6O+oAA7CXDpO8Wqj2
LIxyh6mx/H9z/WNxeKWHWc8w4Q0QshNabYL1auaAn6AFC2jkR2vHat+2/XcycuUY
+gn0oJMsXdKMdYV2ZZAMA3m3MSNjrXiDCYZohMr/+c8mmpJ5581LxedhpxfL86kS
k5Nrp+gvU5LEYFiwzAJRGFuFjWJZY7attN6a+yb3ACfAXVU3dJnJUH/jWS5E4ywl
7uxMMne0nxrpS10gxdr9HIcWxkPo1LsmmkVwXqkLN1PiRnsn/eBG8om3zEK2yygm
btmlyTrIQRNg91CMFa6ybRoVGld45pIq2WWQgj9sAq+uEjonljYE1x2igGOpm/Hl
urR8FLBOybEfdF849lHqm/osohHUqS0nGkWxr7JOcQ3AWEbWaQbLU8uz/mtBzUF+
fUwPfHJ5elnNXkoOrJupmHN5fLT0zLm4BwyydFy4x2+IoZCn9Kr5v2c69BoVYh63
n749sSmvZ6ES8lgQGVMDMBu4Gon2nL2XA46jCfMdiyHxtN/kHNGfZQIG6lzWE7OE
76KlXIx3KadowGuuQNKotOrN8I1LOJwZmhsoVLiJkO/KdYE+HvJkJMcYr07/R54H
9jVlpNMKVv/1F2Rs76giJUmTtt8AF9pYfl3uxRuw0dFfIRDH+fO6AgonB8Xx1sfT
4PsJYGw=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
YyRIHN8wfdVoOw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB8jCCAXigAwIBAgITBmyf18G7EEwpQ+Vxe3ssyBrBDjAKBggqhkjOPQQDAzA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSA0MB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
Q0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN/sGKe0uoe0ZLY7Bi
9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri83Bk
M6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKNCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFNPsxzplbszh2naaVvuc84ZtV+WB
MAoGCCqGSM49BAMDA2gAMGUCMDqLIfG9fhGt0O9Yli/W651+kI0rz2ZVwyzjKKlw
CkcO8DdZEv8tmZQoTipPNU0zWgIxAOp1AE47xDqUEpHJWEadIRNyp4iciuRMStuW
1KyLa2tJElMzrdfkviT8tQp21KW8EA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID7zCCAtegAwIBAgIBADANBgkqhkiG9w0BAQsFADCBmDELMAkGA1UEBhMCVVMx
EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoT
HFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xOzA5BgNVBAMTMlN0YXJmaWVs
ZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5
MDkwMTAwMDAwMFoXDTM3MTIzMTIzNTk1OVowgZgxCzAJBgNVBAYTAlVTMRAwDgYD
VQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFy
ZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTswOQYDVQQDEzJTdGFyZmllbGQgU2Vy
dmljZXMgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANUMOsQq+U7i9b4Zl1+OiFOxHz/Lz58gE20p
OsgPfTz3a3Y4Y9k2YKibXlwAgLIvWX/2h/klQ4bnaRtSmpDhcePYLQ1Ob/bISdm2
8xpWriu2dBTrz/sm4xq6HZYuajtYlIlHVv8loJNwU4PahHQUw2eeBGg6345AWh1K
Ts9DkTvnVtYAcMtS7nt9rjrnvDH5RfbCYM8TWQIrgMw0R9+53pBlbQLPLJGmpufe
hRhJfGZOozptqbXuNC66DQO4M99H67FrjSXZm86B0UVGMpZwh94CDklDhbZsc7tk
6mFBrMnUVN+HL8cisibMn1lUaJ/8viovxFUcdUBgF4UCVTmLfwUCAwEAAaNCMEAw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJxfAN+q
AdcwKziIorhtSpzyEZGDMA0GCSqGSIb3DQEBCwUAA4IBAQBLNqaEd2ndOxmfZyMI
bw5hyf2E3F/YNoHN2BtBLZ9g3ccaaNnRbobhiCPPE95Dz+I0swSdHynVv/heyNXB
ve6SbzJ08pGCL72CQnqtKrcgfU28elUSwhXqvfdqlS5sdJ/PHLTyxQGjhdByPq1z
qwubdQxtRbeOlKyWN7Wg0I8VRw7j6IPdj/3vQQF3zCepYoUz8jcI73HPdwbeyBkd
iEDPfUYd/x7H4c7/I9vG+o1VTqkC50cRRj70/b17KSa7qWFiNyi2LSr2EIZkyXCn
0q23KXB56jzaYyWf/Wi3MOxw+3WKt21gZ7IeyLnp2KhvAotnDU0mV3HaIPzBSlCN
sSi6
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID5DCCAsygAwIBAgITBntQTYPTyyjojPpIvZY3qGHvkjANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MTAyMTIyMjExOVoXDTM3MTIzMTAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN/sGKe0uoe0ZL
Y7Bi9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri
83BkM6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKOCATEwggEtMA8GA1UdEwEB
/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTT7Mc6ZW7M4dp2mlb7
nPOGbVflgTAfBgNVHSMEGDAWgBScXwDfqgHXMCs4iKK4bUqc8hGRgzB4BggrBgEF
BQcBAQRsMGowLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLnJvb3RnMi5hbWF6b250
cnVzdC5jb20wOAYIKwYBBQUHMAKGLGh0dHA6Ly9jcmwucm9vdGcyLmFtYXpvbnRy
dXN0LmNvbS9yb290ZzIuY2VyMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwu
cm9vdGcyLmFtYXpvbnRydXN0LmNvbS9yb290ZzIuY3JsMBEGA1UdIAQKMAgwBgYE
VR0gADANBgkqhkiG9w0BAQsFAAOCAQEAF3mt42HgwmotsJFevpdpgIOw/YdRPrRX
nrWBvf+PoyqZ5oyb1I92hTHST4Mj1juRw5oymBmx/3HA8IECIQG+uCQv3qdTm8xk
Nt9cVt8H1w4Sl6EPlT0b/Zy4zqNdN689yAxT7z9GStsgS3eGXQq6LrsABVDZ9yev
UM9EoFnxOfwix1hjHaaUw+m5zprwAawanvTHg5Fv0NQ1XZJqh1rY++i2saHbu7mL
ANG6m4F1aUcpKY5WzOiKesadGWqsNy2n2ZfceEoXRPFpA8ldQktNBiL7MO2SEmj8
Yt/5HN2eEldSGsiVPO11+qgWaqYHkR4mzfayZZbBp2pDkCkLo28LCw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICuzCCAmGgAwIBAgITBn+UV1j+VbnuP3WDHUfwfSJsijAKBggqhkjOPQQDAjA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSAzMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENBIDNB
MQ8wDQYDVQQDEwZBbWF6b24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYcYsK
mYdR0Gj8Xz45E/lfcTTnXhg2EtAIYBIHyXv/ZQyyyCas1aptX/I5T1coT6XK181g
nB8hADuKfWlNoIYRo4IBOTCCATUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
Af8EBAMCAYYwHQYDVR0OBBYEFATc4JXl6LlrlKHvjFsxHhN+VZfaMB8GA1UdIwQY
MBaAFKu229cGnjesMIYHkXDHnMQZsXjAMHsGCCsGAQUFBwEBBG8wbTAvBggrBgEF
BQcwAYYjaHR0cDovL29jc3Aucm9vdGNhMy5hbWF6b250cnVzdC5jb20wOgYIKwYB
BQUHMAKGLmh0dHA6Ly9jcnQucm9vdGNhMy5hbWF6b250cnVzdC5jb20vcm9vdGNh
My5jZXIwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5yb290Y2EzLmFtYXpv
bnRydXN0LmNvbS9yb290Y2EzLmNybDARBgNVHSAECjAIMAYGBFUdIAAwCgYIKoZI
zj0EAwIDSAAwRQIgOl/vux0qfxNm05W3eofa9lKwz6oKvdu6g6Sc0UlwgRcCIQCS
WSQ6F6JHLoeOWLyFFF658eNKEKbkEGMHz34gLX/N3g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGRzCCBC+gAwIBAgITBntQWOJkLBqShIusDbGvAKDiIDANBgkqhkiG9w0BAQwF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAyMB4XDTE1MTAyMTIyMjM1MFoXDTQwMTAyMTIyMjM1MFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDJBMQ8wDQYDVQQDEwZBbWF6b24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC0P8hSLewmrZ41CCPBQytZs5NBFMq5ztbnMf+kZUp9S25LPfjNW3zgC/6E
qCTWNVMMHhq7ez9IQJk48qbfBTLlZkuKnUWbA9vowrDfcxUN0mRE4B/TJbveXyTf
vE91iDlqDrERecE9D8sdjzURrtHTp27lZdRkXFvfEVCq4hl3sHkzjodisaQthLp1
gLsiA7vKt+8zcL4Aeq52UyYb8r4/jdZ3KaQp8O/T4VwDCRKm8ey3kttpJWaflci7
eRzNjY7gE3NMANVXCeQwOBfH2GjINFCObmPsqiBuoAnsv2k5aQLNoU1OZk08ClXm
mEZ2rI5qZUTX1HuefBJnpMkPugFCw8afaHnB13SkLE7wxX8SZRdDIe5WiwyDL1tR
2+8lpz4JsMoFopHmD3GaHyjbN+hkOqHgLltwewOsiyM0u3CZphypN2KeD+1FLjnY
TgdIAd1FRgK2ZXDDrEdjnsSEfShKf0l4mFPSBs9E3U6sLmubDRXKLLLpa/dF4eKu
LEKS1bXYT28iM6D5gSCnzho5G4d18jQD/slmc5XmRo5Pig0RyBwDaLuxeIZuiJ0A
J6YFhffbrLYF5dEQl0cU+t3VBK5u/o1WkWXsZawU038lWn/AXerodT/pAcrtWA4E
NQEN09WEKMhZVPhqdwhF/Gusr04mQtKt7T2v6UMQvtVglv5E7wIDAQABo4IBOTCC
ATUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYE
FNpDStD8AcBLv1gnjHbNCoHzlC70MB8GA1UdIwQYMBaAFLAM8Eww9AVYAkj9M+VS
r0uE42ZSMHsGCCsGAQUFBwEBBG8wbTAvBggrBgEFBQcwAYYjaHR0cDovL29jc3Au
cm9vdGNhMi5hbWF6b250cnVzdC5jb20wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcmwu
cm9vdGNhMi5hbWF6b250cnVzdC5jb20vcm9vdGNhMi5jZXIwPwYDVR0fBDgwNjA0
oDKgMIYuaHR0cDovL2NybC5yb290Y2EyLmFtYXpvbnRydXN0LmNvbS9yb290Y2Ey
LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBAJikCSCv
GJSNKA+vlHBPDrO6Yng6siOpHCMlfyv0CZ1R44K1+p/rt0bGo4LVpxhhHAW7HznM
fohYn/fEL+LoJjLQYuZzRqwOFBGPp7Uhw2SMwtTApAHP4lWzIPFYSmZGJpSlj8sX
FbLAl0zFZD9rivbfS0Ue1c9JhtN/fi8ft9HD93ZipFD3MlECTnPQ02q6vrQsWNpz
W1z/1Bq7gatG3x5OywYniAA3DGejleXwY7ZhgsyK1rESoHHsrlw2/htSUFTblTqI
JL+W7XKzReocwrEahja+7CeEdeYDHdiH2EG3FbOB0BcSi2Rp0sjEkQDYzDqL5uSn
QSbXkc93bIf9byo3Gbwm/TNnt4U9bTuSkU1SLPJpPvxZB4IOo7tAUuc2i4dN00H5
wxUDSYfShSY+nPdvcqjvlqpfGqg88ARe+WpPTOPNJvDgHbAni/+NtoQdaH9Z0Yel
iMGau/tNlVj7Vc1EgEyRjJdBe9gBQIbb4OZqs4GdnS2y0pzuUFY0mfhmJgcajnwx
Go42XkB7MxLjr60vnFhWN+alijo5SCchBaOgzw2so0AeVVFVE8lP56EtcNGqmUp0
wNseSG0jCCcXKE8OorP26h9bmsGMCudCIysud4RJYjpCN7Kb/iPQUbbXMn5h6jDw
c0NRIWYT/a0Ci2STLqAOGvf9PEgFXoWxnqN2
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEdTCCA12gAwIBAgIJAKcOSkw0grd/MA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNV
BAYTAlVTMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTIw
MAYDVQQLEylTdGFyZmllbGQgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
eTAeFw0wOTA5MDIwMDAwMDBaFw0zNDA2MjgxNzM5MTZaMIGYMQswCQYDVQQGEwJV
UzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UE
ChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjE7MDkGA1UEAxMyU3RhcmZp
ZWxkIFNlcnZpY2VzIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVDDrEKvlO4vW+GZdfjohTsR8/
y8+fIBNtKTrID30892t2OGPZNmCom15cAICyL1l/9of5JUOG52kbUpqQ4XHj2C0N
Tm/2yEnZtvMaVq4rtnQU68/7JuMauh2WLmo7WJSJR1b/JaCTcFOD2oR0FMNnngRo
Ot+OQFodSk7PQ5E751bWAHDLUu57fa4657wx+UX2wmDPE1kCK4DMNEffud6QZW0C
zyyRpqbn3oUYSXxmTqM6bam17jQuug0DuDPfR+uxa40l2ZvOgdFFRjKWcIfeAg5J
Q4W2bHO7ZOphQazJ1FTfhy/HIrImzJ9ZVGif/L4qL8RVHHVAYBeFAlU5i38FAgMB
AAGjgfAwge0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0O
BBYEFJxfAN+qAdcwKziIorhtSpzyEZGDMB8GA1UdIwQYMBaAFL9ft9HO3R+G9FtV
rNzXEMIOqYjnME8GCCsGAQUFBwEBBEMwQTAcBggrBgEFBQcwAYYQaHR0cDovL28u
c3MyLnVzLzAhBggrBgEFBQcwAoYVaHR0cDovL3guc3MyLnVzL3guY2VyMCYGA1Ud
HwQfMB0wG6AZoBeGFWh0dHA6Ly9zLnNzMi51cy9yLmNybDARBgNVHSAECjAIMAYG
BFUdIAAwDQYJKoZIhvcNAQELBQADggEBACMd44pXyn3pF3lM8R5V/cxTbj5HD9/G
VfKyBDbtgB9TxF00KGu+x1X8Z+rLP3+QsjPNG1gQggL4+C/1E2DUBc7xgQjB3ad1
l08YuW3e95ORCLp+QCztweq7dp4zBncdDQh/U90bZKuCJ/Fp1U1ervShw3WnWEQt
8jxwmKy6abaVd38PMV4s/KCHOkdp8Hlf9BRUpJVeEXgSYCfOn8J3/yNTd126/+pZ
59vPr5KW7ySaNRB6nJHGDn2Z9j8Z3/VyVOEVqQdZe4O/Ui5GjLIAZHYcSNPYeehu
VsyuLAOQ1xk4meTKCRlb/weWsKh/NEnfVqn3sF/tM+2MR7cwA130A4w=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEdTCCA12gAwIBAgIJANjJM0P+XTkpMA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNV
BAYTAlVTMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTIw
MAYDVQQLEylTdGFyZmllbGQgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
eTAeFw0wOTA4MzAwMDAwMDBaFw0zNDA2MjgxODAwMDBaMIGYMQswCQYDVQQGEwJV
UzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UE
ChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjE7MDkGA1UEAxMyU3RhcmZp
ZWxkIFNlcnZpY2VzIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVDDrEKvlO4vW+GZdfjohTsR8/
y8+fIBNtKTrID30892t2OGPZNmCom15cAICyL1l/9of5JUOG52kbUpqQ4XHj2C0N
Tm/2yEnZtvMaVq4rtnQU68/7JuMauh2WLmo7WJSJR1b/JaCTcFOD2oR0FMNnngRo
Ot+OQFodSk7PQ5E751bWAHDLUu57fa4657wx+UX2wmDPE1kCK4DMNEffud6QZW0C
zyyRpqbn3oUYSXxmTqM6bam17jQuug0DuDPfR+uxa40l2ZvOgdFFRjKWcIfeAg5J
Q4W2bHO7ZOphQazJ1FTfhy/HIrImzJ9ZVGif/L4qL8RVHHVAYBeFAlU5i38FAgMB
AAGjgfAwge0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0O
BBYEFJxfAN+qAdcwKziIorhtSpzyEZGDMB8GA1UdIwQYMBaAFL9ft9HO3R+G9FtV
rNzXEMIOqYjnME8GCCsGAQUFBwEBBEMwQTAcBggrBgEFBQcwAYYQaHR0cDovL28u
c3MyLnVzLzAhBggrBgEFBQcwAoYVaHR0cDovL3guc3MyLnVzL3guY2VyMCYGA1Ud
HwQfMB0wG6AZoBeGFWh0dHA6Ly9zLnNzMi51cy9yLmNybDARBgNVHSAECjAIMAYG
BFUdIAAwDQYJKoZIhvcNAQELBQADggEBAFg2BzSkeJ19IPlQijzXPYRZEQnTjtFF
a5d5aSZCk6JTcsq9dtgat6bQKkpDz7RETHpz9B7n1LJeLMOAcQuVjF65CCavDmp0
aw17VmC63u7Z4tNWupeSPSuKCGkIwofgBhBC7PsZrszaKHO1TkAcWDGWHnjVTMht
4sfv66jepOqUBClYXmRsCdxXqlKCjJHUptov3ho4ANG9RZXTn13p36AU1tyZ1iFi
WghNWnoXQ8UdcIZiX5y7D6HMZ6CcCt59vSLRMsYX8Bw/jWV8M+N4mr+F5ydmSq5J
BkV9W9BzwNXiOxwWcLbidb1N28HhoMlQhihpxsUpIgD2WtsQgeaNjUA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgITBntQSu8k7aSeV/dHSEVj9OKhWDANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MTAyMTIyMjA0NVoXDTM3MTIzMTAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaOCATEwggEtMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgGGMB0GA1UdDgQWBBSEGMyFNOy8DJSULghZnMeyEE4KCDAfBgNVHSMEGDAW
gBScXwDfqgHXMCs4iKK4bUqc8hGRgzB4BggrBgEFBQcBAQRsMGowLgYIKwYBBQUH
MAGGImh0dHA6Ly9vY3NwLnJvb3RnMi5hbWF6b250cnVzdC5jb20wOAYIKwYBBQUH
MAKGLGh0dHA6Ly9jcmwucm9vdGcyLmFtYXpvbnRydXN0LmNvbS9yb290ZzIuY2Vy
MD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwucm9vdGcyLmFtYXpvbnRydXN0
LmNvbS9yb290ZzIuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsF
AAOCAQEAY7ItFmzGZlk1ae7URE8CTUg2qZlmSCFugdXGuQZ+/tFHLxolCdmw2Jfn
PX367cbcElUhFvLFRtLwW99VYVqKLA1ypmrs5uuMGOXUUmPA6hU+2dovhh5KuClm
58gz2fH7Gw+V9ko2CRt0XXDmXMJzXxRW1CgcNC05RXnD8J92iMyrok1KnB4+emMU
kNBrcaE+XuqRuAc7lJ9qv4t+JYtEszz3k+Q68TlOOIp0W5k5Xvsx0Q+/r6qCOECs
JP9dLmsuIA/SrhyqW5qTvul/X7nJLlffGWYsbOdmrUzA6fZR9NeL/Ljlx98/ouE3
4dmgCQgWbRp4XTnGnL3XLbVPUAReEQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBn+UV1CMZIwJymUucXkYMOclkjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAMHbSWHRFMzGNIE0qhN6gnRahTrTU
CDPwe7l9/q0IA+QBlrpUHnlAreetYeH1jB8uF3qXXzy22gpBU7NqulTkqSPByT1J
xOhpT2FpO5R3VAdMPdWfSEgtrED0jkmyUQrR1T+/A+nBLdJZeQcl+OqLgeY790JM
JJTsJnnI6FBWeTGhcDI4Y+n3KS3QCVePeWI7jx1dhrHcXH+QDX8Ywe31hV7YENdr
HDpUXrjK6eHN8gazy8G6pndXHFwHp4auiZbJbYAk/q1peOTRagD2JojcLkm+i3cD
843t4By6YT/PVlePU2PCWejkrJQnKQAPOov7IA8kuO2RDWuzE/zF6Hotdg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDxzCCAq+gAwIBAgITBn+USjDPzE90tfUwblTTt74KwzANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MDUyNTEyMDAwMFoXDTM3MTIzMTAxMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG
8lKlui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjr
Zt6jggExMIIBLTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNV
HQ4EFgQUq7bb1waeN6wwhgeRcMecxBmxeMAwHwYDVR0jBBgwFoAUnF8A36oB1zAr
OIiiuG1KnPIRkYMweAYIKwYBBQUHAQEEbDBqMC4GCCsGAQUFBzABhiJodHRwOi8v
b2NzcC5yb290ZzIuYW1hem9udHJ1c3QuY29tMDgGCCsGAQUFBzAChixodHRwOi8v
Y3J0LnJvb3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcyLmNlcjA9BgNVHR8ENjA0
MDKgMKAuhixodHRwOi8vY3JsLnJvb3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcy
LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQELBQADggEBAG5Z+hfC
ycAuzqKJ4ClKK5VZUqjH4jYSzu3UVOLvHzoYk0rIVqFjjBJwa/L5MreP219CIdIX
di3s9at8ZZR+tKsD4T02ZqO/43FQqnSkzF/G+OxYo3malxhuT9j7bNiA9WkCuqVV
bUncQt79aEjDKht7viKQnoybiHB6dtWAXMNObcCviQMqTcoV+sQOpKJMvQanxUk+
fKQLGKlkpu9zKNr2kWdx874JVpYhDCUzW2RX9TtQ04VT6J0xTEew55OJj02jNxHu
Gijg0YLZtWLNWEXkNDkVpZozXbhuTM6GJKhwLn2rmgRgtFTWUDbeq3YE/7NHu+3a
LOL51JEnEI+4hac=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICuzCCAmGgAwIBAgITBntQWZ+RD/WnD+gWjSQKmnxUxDAKBggqhkjOPQQDAjA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSAzMB4XDTE1MTAyMTIyMjQwMFoXDTQwMTAyMTIyMjQwMFowRjELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENBIDNB
MQ8wDQYDVQQDEwZBbWF6b24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYcYsK
mYdR0Gj8Xz45E/lfcTTnXhg2EtAIYBIHyXv/ZQyyyCas1aptX/I5T1coT6XK181g
nB8hADuKfWlNoIYRo4IBOTCCATUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
Af8EBAMCAYYwHQYDVR0OBBYEFATc4JXl6LlrlKHvjFsxHhN+VZfaMB8GA1UdIwQY
MBaAFKu229cGnjesMIYHkXDHnMQZsXjAMHsGCCsGAQUFBwEBBG8wbTAvBggrBgEF
BQcwAYYjaHR0cDovL29jc3Aucm9vdGNhMy5hbWF6b250cnVzdC5jb20wOgYIKwYB
BQUHMAKGLmh0dHA6Ly9jcmwucm9vdGNhMy5hbWF6b250cnVzdC5jb20vcm9vdGNh
My5jZXIwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5yb290Y2EzLmFtYXpv
bnRydXN0LmNvbS9yb290Y2EzLmNybDARBgNVHSAECjAIMAYGBFUdIAAwCgYIKoZI
zj0EAwIDSAAwRQIhAKUn4BOp3rS4iXpFUfnMKCDG93zHSSOAQ3bGYNMlETCyAiBe
rvWmXKDzN/xqO9lOr34ZW0spt7oTbW9q0XNVetCxyQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFkjCCBHqgAwIBAgITBntQS7HVJoW/c+MHCwG6/rJ0QzANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MTAyMTIyMjA1NVoXDTM3MTIzMTAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK2Wny2cSkxK
gXlRmeyKy2tgURO8TW0G/LAIjd0ZEGrHJgw12MBvIITplLGbhQPDW9tK6Mj4kHbZ
W0/jTOgGNk3Mmqw9DJArktQGGWCsN0R5hYGCrVo34A3MnaZMUnbqQ523BNFQ9lXg
1dKmSYXpN+nKfq5clU1Imj+uIFptiJXZNLhSGkOQsL9sBbm2eLfq0OQ6PBJTYv9K
8nu+NQWpEjTj82R0Yiw9AElaKP4yRLuH3WUnAnE72kr3H9rN9yFVkE8P7K6C4Z9r
2UXTu/Bfh+08LDmG2j/e7HJV63mjrdvdfLC6HM783k81ds8P+HgfajZRRidhW+me
z/CiVX18JYpvL7TFz4QuK/0NURBs+18bvBt+xa47mAExkv8LV/SasrlX6avvDXbR
8O70zoan4G7ptGmh32n2M8ZpLpcTnqWHsFcQgTfJU7O7f/aS0ZzQGPSSbtqDT6Zj
mUyl+17vIWR6IF9sZIUVyzfpYgwLKhbcAS4y2j5L9Z469hdAlO+ekQiG+r5jqFoz
7Mt0Q5X5bGlSNscpb/xVA1wf+5+9R+vnSUeVC06JIglJ4PVhHvG/LopyboBZ/1c6
+XUyo05f7O0oYtlNc/LMgRdg7c3r3NunysV+Ar3yVAhU/bQtCSwXVEqY0VThUWcI
0u1ufm8/0i2BWSlmy5A5lREedCf+3euvAgMBAAGjggExMIIBLTAPBgNVHRMBAf8E
BTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUsAzwTDD0BVgCSP0z5VKv
S4TjZlIwHwYDVR0jBBgwFoAUnF8A36oB1zArOIiiuG1KnPIRkYMweAYIKwYBBQUH
AQEEbDBqMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5yb290ZzIuYW1hem9udHJ1
c3QuY29tMDgGCCsGAQUFBzAChixodHRwOi8vY3JsLnJvb3RnMi5hbWF6b250cnVz
dC5jb20vcm9vdGcyLmNlcjA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLnJv
b3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcyLmNybDARBgNVHSAECjAIMAYGBFUd
IAAwDQYJKoZIhvcNAQELBQADggEBAGgVclxgRMQaE30mvpPUzj7RgFJaF5SB1l81
qlYliC2tJYfTwXUQf3+MvI9xT6wzTVt54gD+sEu5wc2yPIApi854CZccm1Yay3JH
DUFAb7bXLQBOvFStlkFl8/u4DKE96FgbsFWpjhf6tlfLh7hgKbICRL1TbQa4Vzbd
DuZ19nPhVhtZ/KFmCxT2Nqph/4ZY2VNWgmoi7fGW7mqDiB2NhZlCaaDr00rgi8gI
6pTwCEp5ffbv1s3mKPWqMl/jAJa90xk/GcEP64wo6dGgJnBsnghywQvnngrmEpdm
8ITiIJfKlBszRYscvPO7ZAwMUVUjO0bGKW5QLbOpNTN/bdvjqjo=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID5DCCAsygAwIBAgITBn+USnERqsPqc7pMrAdXJpbfizANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MDUyNTEyMDAwMFoXDTM3MTIzMTAxMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN/sGKe0uoe0ZL
Y7Bi9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri
83BkM6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKOCATEwggEtMA8GA1UdEwEB
/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTT7Mc6ZW7M4dp2mlb7
nPOGbVflgTAfBgNVHSMEGDAWgBScXwDfqgHXMCs4iKK4bUqc8hGRgzB4BggrBgEF
BQcBAQRsMGowLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLnJvb3RnMi5hbWF6b250
cnVzdC5jb20wOAYIKwYBBQUHMAKGLGh0dHA6Ly9jcnQucm9vdGcyLmFtYXpvbnRy
dXN0LmNvbS9yb290ZzIuY2VyMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwu
cm9vdGcyLmFtYXpvbnRydXN0LmNvbS9yb290ZzIuY3JsMBEGA1UdIAQKMAgwBgYE
VR0gADANBgkqhkiG9w0BAQsFAAOCAQEAeyHnnDOGsjKqSrdQibquHlGrrtMjqGnK
/m7dZLQCB/VZxYEp2OhR4I/Lf8s9B9WcaGKvyscPiovgVKhwSr5NzEfhqXQE7YT/
bbfVBWqRyfTEZ8x44095xFCPErRpQOddBWmPW4byBwnmUeOlS8tFEdYi9PXD38b5
OY7/j2YRsShyvzKre7+C/8aQBOrt1Q0sfJYDxq4Chx6YWpf1YqikV7DL/AKi2zxm
+Vq+Vx7yntdcKzEDKluFweG0OHAHXy6VoVNeifx0gRks5harEpgtibf8dxDWVuRs
mWYARW/NX/vSzAG25AaCKROgcXR7gvL9xmDslFGwaO4bgc/Q9IrcUg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGRzCCBC+gAwIBAgITBn+UV1Xxh6kfgWPz5iRiAXf/ODANBgkqhkiG9w0BAQwF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAyMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDJBMQ8wDQYDVQQDEwZBbWF6b24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC0P8hSLewmrZ41CCPBQytZs5NBFMq5ztbnMf+kZUp9S25LPfjNW3zgC/6E
qCTWNVMMHhq7ez9IQJk48qbfBTLlZkuKnUWbA9vowrDfcxUN0mRE4B/TJbveXyTf
vE91iDlqDrERecE9D8sdjzURrtHTp27lZdRkXFvfEVCq4hl3sHkzjodisaQthLp1
gLsiA7vKt+8zcL4Aeq52UyYb8r4/jdZ3KaQp8O/T4VwDCRKm8ey3kttpJWaflci7
eRzNjY7gE3NMANVXCeQwOBfH2GjINFCObmPsqiBuoAnsv2k5aQLNoU1OZk08ClXm
mEZ2rI5qZUTX1HuefBJnpMkPugFCw8afaHnB13SkLE7wxX8SZRdDIe5WiwyDL1tR
2+8lpz4JsMoFopHmD3GaHyjbN+hkOqHgLltwewOsiyM0u3CZphypN2KeD+1FLjnY
TgdIAd1FRgK2ZXDDrEdjnsSEfShKf0l4mFPSBs9E3U6sLmubDRXKLLLpa/dF4eKu
LEKS1bXYT28iM6D5gSCnzho5G4d18jQD/slmc5XmRo5Pig0RyBwDaLuxeIZuiJ0A
J6YFhffbrLYF5dEQl0cU+t3VBK5u/o1WkWXsZawU038lWn/AXerodT/pAcrtWA4E
NQEN09WEKMhZVPhqdwhF/Gusr04mQtKt7T2v6UMQvtVglv5E7wIDAQABo4IBOTCC
ATUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYE
FNpDStD8AcBLv1gnjHbNCoHzlC70MB8GA1UdIwQYMBaAFLAM8Eww9AVYAkj9M+VS
r0uE42ZSMHsGCCsGAQUFBwEBBG8wbTAvBggrBgEFBQcwAYYjaHR0cDovL29jc3Au
cm9vdGNhMi5hbWF6b250cnVzdC5jb20wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcnQu
cm9vdGNhMi5hbWF6b250cnVzdC5jb20vcm9vdGNhMi5jZXIwPwYDVR0fBDgwNjA0
oDKgMIYuaHR0cDovL2NybC5yb290Y2EyLmFtYXpvbnRydXN0LmNvbS9yb290Y2Ey
LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBAEO5W+iF
yChjDyyrmiwFupVWQ0Xy2ReFNQiZq7XKVHvsLQe01moSLnxcBxioOPBKt1KkZO7w
Gcbmke0+7AxLaG/F5NPnzRtK1/pRhXQ0XdU8pVh/1/h4GoqRlZ/eN0JDarUhZPkV
kSr96LUYDTxcsAidF7zkzWfmtcJg/Aw8mi14xKVEa6aVyKu54c8kKkdlt0WaigOv
Z/xYhxp24AfoFKaIraDNdsD8q2N7eDYeN4WGLzNSlil+iFjzflI9mq1hTuI/ZNjV
rbvob6FUQ8Cc524gMjbpZCNuZ1gfXzwwhGp0AnQF6CJsWF9uwPpZEVFnnnfiWH3M
oup41EvBhqaAqOlny0sm5pI82nRUCAE3DLkJ1+eAtdQaYblZQkQrRyTuPmJEm+5y
QwdDVw6uHc5OsSj/tyhh8zJ2Xq3zgh3dMONGjJEysxGaCoIb+61PWwMy2dIarVwI
r+c+AY+3PrhgBspNdWZ87JzNHii7ksdjUSVGTTy1vGXgPYrv0lp0IMnKaZP58xiw
rDx7uTlQuPVWNOZvCaT3ZcoxTsNKNscIUe+WJjWx5hdzpv/oksDPY5ltZ0j3hlDS
D+Itk95/cNJVRM/0HpxI1SX9MTZtOSJoEDdUtOpVaOuBAvEK4gvTzdt0r5L+fuI6
o5LAuRo/LO1xVRH49KFRoaznzU3Ch9+kbPb3
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC+TCCAn6gAwIBAgITBn+UV1qIYqkHLjI5w3zroSdOGDAKBggqhkjOPQQDAzA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSA0MB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENBIDRB
MQ8wDQYDVQQDEwZBbWF6b24wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASRP0kIW0Ha
7+ORvEVhIS5gIgkH66X5W9vBRTX14oG/1elIyI6LbFZ+E5KAufL0XoWJGI1WbPRm
HW246FKSzF0wOEZZyxEROz6tuaVsnXRHRE76roS/Wr064uJpKH+Lv+SjggE5MIIB
NTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU
pSHN2+tTIZmqytlnQpQlsnv0wuMwHwYDVR0jBBgwFoAU0+zHOmVuzOHadppW+5zz
hm1X5YEwewYIKwYBBQUHAQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5y
b290Y2E0LmFtYXpvbnRydXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5y
b290Y2E0LmFtYXpvbnRydXN0LmNvbS9yb290Y2E0LmNlcjA/BgNVHR8EODA2MDSg
MqAwhi5odHRwOi8vY3JsLnJvb3RjYTQuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTQu
Y3JsMBEGA1UdIAQKMAgwBgYEVR0gADAKBggqhkjOPQQDAwNpADBmAjEA59RAOBaj
uh0rT/OOTWPEv6TBnb9XEadburBaXb8SSrR8il+NdkfS9WXRAzbwrG7LAjEA3ukD
1HrQq+WXHBM5sIuViJI/Zh7MOjsc159Q+dn36PBqLRq03AXqE/lRjnv8C5nj
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBntQWB5VRYI8C6YvYwneX8pJTDANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMTIyMjM0MFoXDTQwMTAyMTIyMjM0MFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NybC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAfO6dSZbEgjuEREF/cAS09ZJBmd+3
lH2lkjpULqhxMMSPwe2NxheHJO46hyp2205IcM/+/zlxUIIViissPDXyrEN6WlQa
7Qhu/UcfCsOdCi1zjbG9Oe1Z2UQhQhHhy8zAE0/SsZaxDkQpdgnyI+oI6sEzLXoQ
JLgiwoM0F6QzB+n18CJPihdmzqCS2Q57gATLED7umyLD0ULvmr6JRa0HyxNAFOIn
YsYBnS9X8mkiVg+1iXsM3GjmownXvCvxG8Wf5DHFhOx9/WaA6C0k+K4tLsO3geYy
W/LI5QFZwJMW6+ieFTjhyI6EzEolo7Z6PWaNB4X26611NpZ1IrWn56hFCw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgITBn+USionzfP6wq4rAfkI7rnExjANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MDUyNTEyMDAwMFoXDTM3MTIzMTAxMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaOCATEwggEtMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgGGMB0GA1UdDgQWBBSEGMyFNOy8DJSULghZnMeyEE4KCDAfBgNVHSMEGDAW
gBScXwDfqgHXMCs4iKK4bUqc8hGRgzB4BggrBgEFBQcBAQRsMGowLgYIKwYBBQUH
MAGGImh0dHA6Ly9vY3NwLnJvb3RnMi5hbWF6b250cnVzdC5jb20wOAYIKwYBBQUH
MAKGLGh0dHA6Ly9jcnQucm9vdGcyLmFtYXpvbnRydXN0LmNvbS9yb290ZzIuY2Vy
MD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwucm9vdGcyLmFtYXpvbnRydXN0
LmNvbS9yb290ZzIuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsF
AAOCAQEAYjdCXLwQtT6LLOkMm2xF4gcAevnFWAu5CIw+7bMlPLVvUOTNNWqnkzSW
MiGpSESrnO09tKpzbeR/FoCJbM8oAxiDR3mjEH4wW6w7sGDgd9QIpuEdfF7Au/ma
eyKdpwAJfqxGF4PcnCZXmTA5YpaP7dreqsXMGz7KQ2hsVxa81Q4gLv7/wmpdLqBK
bRRYh5TmOTFffHPLkIhqhBGWJ6bt2YFGpn6jcgAKUj6DiAdjd4lpFw85hdKrCEVN
0FE6/V1dN2RMfjCyVSRCnTawXZwXgWHxyvkQAiSr6w10kY17RSlQOYiypok1JR4U
akcjMS9cmvqtmg5iUaQqqcT5NJ0hGA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFkjCCBHqgAwIBAgITBn+USi+ZU51QWu3y3j7YVwHmyjANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MDUyNTEyMDAwMFoXDTM3MTIzMTAxMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK2Wny2cSkxK
gXlRmeyKy2tgURO8TW0G/LAIjd0ZEGrHJgw12MBvIITplLGbhQPDW9tK6Mj4kHbZ
W0/jTOgGNk3Mmqw9DJArktQGGWCsN0R5hYGCrVo34A3MnaZMUnbqQ523BNFQ9lXg
1dKmSYXpN+nKfq5clU1Imj+uIFptiJXZNLhSGkOQsL9sBbm2eLfq0OQ6PBJTYv9K
8nu+NQWpEjTj82R0Yiw9AElaKP4yRLuH3WUnAnE72kr3H9rN9yFVkE8P7K6C4Z9r
2UXTu/Bfh+08LDmG2j/e7HJV63mjrdvdfLC6HM783k81ds8P+HgfajZRRidhW+me
z/CiVX18JYpvL7TFz4QuK/0NURBs+18bvBt+xa47mAExkv8LV/SasrlX6avvDXbR
8O70zoan4G7ptGmh32n2M8ZpLpcTnqWHsFcQgTfJU7O7f/aS0ZzQGPSSbtqDT6Zj
mUyl+17vIWR6IF9sZIUVyzfpYgwLKhbcAS4y2j5L9Z469hdAlO+ekQiG+r5jqFoz
7Mt0Q5X5bGlSNscpb/xVA1wf+5+9R+vnSUeVC06JIglJ4PVhHvG/LopyboBZ/1c6
+XUyo05f7O0oYtlNc/LMgRdg7c3r3NunysV+Ar3yVAhU/bQtCSwXVEqY0VThUWcI
0u1ufm8/0i2BWSlmy5A5lREedCf+3euvAgMBAAGjggExMIIBLTAPBgNVHRMBAf8E
BTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUsAzwTDD0BVgCSP0z5VKv
S4TjZlIwHwYDVR0jBBgwFoAUnF8A36oB1zArOIiiuG1KnPIRkYMweAYIKwYBBQUH
AQEEbDBqMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5yb290ZzIuYW1hem9udHJ1
c3QuY29tMDgGCCsGAQUFBzAChixodHRwOi8vY3J0LnJvb3RnMi5hbWF6b250cnVz
dC5jb20vcm9vdGcyLmNlcjA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLnJv
b3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcyLmNybDARBgNVHSAECjAIMAYGBFUd
IAAwDQYJKoZIhvcNAQELBQADggEBAEAYjKahC5+1WtSuad6bxr0iozuII35V12r0
0D59cm/zWGLHSsoOcn5NK1vM+0zpUo2npQAG5OvmsBKtBQAZVqIhUdDFW06CQhr/
PERxcFwiNa3FzjJ0eS136pv0GMLKDmMXdpjWNUAcRFMbgHlNNBjoSxTN9SdbD+kr
WWjAw1wsDfp8B9lZFfOGX4Op9F1WmY80o+K4gTjXFEqyCDfrvrH3+P6dI2to/LTB
dAezXg033EtLUw69atCLtd8r8TIMAE2IGFt5rHg4sEG6NYPXkOrQqs6JLaFxibKq
669TfBlcloGLc80dG96ryjpNIzEUtT5Eyc6KIl1Z/I09iBxEWQM=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDxzCCAq+gAwIBAgITBntQTK1yKJpG6coUD6IU6G+KAjANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MTAyMTIyMjEwOFoXDTM3MTIzMTAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG
8lKlui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjr
Zt6jggExMIIBLTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNV
HQ4EFgQUq7bb1waeN6wwhgeRcMecxBmxeMAwHwYDVR0jBBgwFoAUnF8A36oB1zAr
OIiiuG1KnPIRkYMweAYIKwYBBQUHAQEEbDBqMC4GCCsGAQUFBzABhiJodHRwOi8v
b2NzcC5yb290ZzIuYW1hem9udHJ1c3QuY29tMDgGCCsGAQUFBzAChixodHRwOi8v
Y3JsLnJvb3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcyLmNlcjA9BgNVHR8ENjA0
MDKgMKAuhixodHRwOi8vY3JsLnJvb3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcy
LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQELBQADggEBAIXyklZn
uErLXrrmLkDv1ahRR8GAMrojOalie+eTj8mQKoVdogT1TJjHmWeXbqjteKWjmh1I
rEsozJ+rXRWDFE5OfwMq8gQNuOu7pylaQsQU+IUlyJ4mvQmOVtkw7B+Qst5MCjm6
UOFhLITZTVxIeuxHb5zyJhUlCGGJ+iwPfU3o7Lo80ITexGS1wPi6X5faIacIZc5d
BRSc2oPRBE7/o0rr7U4cIbbxwAoyGX1V1FcWR55jrSXviLo7K9PSr/MjX6BqRhgZ
AutYYTRwRE/GyjMGmccXk3DtkbMn4AOBVHf8ytR4lKNJY382V1YfcReQlDq5Z70J
s7bi2B/RugkwhAo=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC+TCCAn6gAwIBAgITBntQWlAVP2IAmmEoOCD51IrWAjAKBggqhkjOPQQDAzA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSA0MB4XDTE1MTAyMTIyMjQwOVoXDTQwMTAyMTIyMjQwOVowRjELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENBIDRB
MQ8wDQYDVQQDEwZBbWF6b24wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASRP0kIW0Ha
7+ORvEVhIS5gIgkH66X5W9vBRTX14oG/1elIyI6LbFZ+E5KAufL0XoWJGI1WbPRm
HW246FKSzF0wOEZZyxEROz6tuaVsnXRHRE76roS/Wr064uJpKH+Lv+SjggE5MIIB
NTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU
pSHN2+tTIZmqytlnQpQlsnv0wuMwHwYDVR0jBBgwFoAU0+zHOmVuzOHadppW+5zz
hm1X5YEwewYIKwYBBQUHAQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5y
b290Y2E0LmFtYXpvbnRydXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NybC5y
b290Y2E0LmFtYXpvbnRydXN0LmNvbS9yb290Y2E0LmNlcjA/BgNVHR8EODA2MDSg
MqAwhi5odHRwOi8vY3JsLnJvb3RjYTQuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTQu
Y3JsMBEGA1UdIAQKMAgwBgYEVR0gADAKBggqhkjOPQQDAwNpADBmAjEAgCWXqLiS
KirNx/HhnI7+1PoaXPvCHLLcMJVNtx0kybogN8VPf8M4tiXUQRav+2sxAjEA0h4v
ZI4c9dDvi8iCPZBGlrn7JzyPUt+AEvnMoW3zplRTZQ5n49gQnOfLz6DXMcCE
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEojCCA4qgAwIBAgITBn+UV0u3B10+SJZceDIkqnVP7TANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDBBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQChhTHcMX+WcSKio/2VJ8N0cCpdrUf4oB9V+fx2dFxU+XgRvszhgePcNKv5
d7a0qOWF9uLmYix0BP34xYujNe0TTGBjOdjCWmTLi9mb5gO8Qxe3eaPZFHX2JbA+
GeqyLkv3/Dt4SkggAZX1PvoaPlCytHCW7qDdo+ycuqwrrfl0fYfJrEA+O5x8v+uH
UmC5APF5vYE8XdGhGra5JRot2TY3P+Kh1AfuJWPLBRgmmbPscv81zVdl+LzZdGFP
dCnCwE9OKd4stKNkO2vTwdJykLgovcF889LQdbPfCx7UaDeHdAcJLyNcS0i5FrHD
7hNfwzfpOORF0+1wF6HdE/GBUJBJAgMBAAGjggE0MIIBMDASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUl+rEItIGGO2FBP/cUsJu
2w4G4T8wHwYDVR0jBBgwFoAUnF8A36oB1zArOIiiuG1KnPIRkYMweAYIKwYBBQUH
AQEEbDBqMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5yb290ZzIuYW1hem9udHJ1
c3QuY29tMDgGCCsGAQUFBzAChixodHRwOi8vY3J0LnJvb3RnMi5hbWF6b250cnVz
dC5jb20vcm9vdGcyLmNlcjA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLnJv
b3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcyLmNybDARBgNVHSAECjAIMAYGBFUd
IAAwDQYJKoZIhvcNAQELBQADggEBAK/GJ9NNlVof/45Jo9qouxV79fiyONjw5Kym
nZpko27O2TQwnSN4xguhR9qPCLJFfzxpybjZK52+bpNpXbWOoZKEsXIFxShocXmx
xY3jpQRDijIqyB1wEEYV/0S4J6dGtdx9xb/t1L6/53ogFPa17v+dFhJQ0WwIzfTW
R/Vox5ZrJ/sgBIgylEJWsEUX0hc+QwryeGU9Ylv2XIcmANzoH2tQnHs1v8GG3FYY
RZ4FeoPETzXfKd98y0l9v6lx2guQ4hNA3vCYDMF+w/2TcVW6YPVMjEkuRN2hypcY
uNmaqaMA0K0ZD7nQOedXceNRfr+GruHRduh2EZI0gMxfOpwfn98=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEojCCA4qgAwIBAgITBntQUp3WX1ga1fXFWlp5GKFvkzANBgkqhkiG9w0BAQsF
ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMB4XDTE1MTAyMTIyMjIyN1oXDTQwMTAyMTIyMjIyN1owRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDBBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQChhTHcMX+WcSKio/2VJ8N0cCpdrUf4oB9V+fx2dFxU+XgRvszhgePcNKv5
d7a0qOWF9uLmYix0BP34xYujNe0TTGBjOdjCWmTLi9mb5gO8Qxe3eaPZFHX2JbA+
GeqyLkv3/Dt4SkggAZX1PvoaPlCytHCW7qDdo+ycuqwrrfl0fYfJrEA+O5x8v+uH
UmC5APF5vYE8XdGhGra5JRot2TY3P+Kh1AfuJWPLBRgmmbPscv81zVdl+LzZdGFP
dCnCwE9OKd4stKNkO2vTwdJykLgovcF889LQdbPfCx7UaDeHdAcJLyNcS0i5FrHD
7hNfwzfpOORF0+1wF6HdE/GBUJBJAgMBAAGjggE0MIIBMDASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUl+rEItIGGO2FBP/cUsJu
2w4G4T8wHwYDVR0jBBgwFoAUnF8A36oB1zArOIiiuG1KnPIRkYMweAYIKwYBBQUH
AQEEbDBqMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5yb290ZzIuYW1hem9udHJ1
c3QuY29tMDgGCCsGAQUFBzAChixodHRwOi8vY3JsLnJvb3RnMi5hbWF6b250cnVz
dC5jb20vcm9vdGcyLmNlcjA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLnJv
b3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcyLmNybDARBgNVHSAECjAIMAYGBFUd
IAAwDQYJKoZIhvcNAQELBQADggEBAGUFWQnstW12HJoKhJv5R2BqmRMdCrlDmUdc
0LyKXrE5lb8FJVCJcoebwtXhBedaIQxxaDZHXbNOPyMFWhE2j2pLEDTKGY4MQRb/
KAUAR6jncl3MQCmVBvRmA4tzwZtNbqWYhb70YUn4KjP+3O8IV86WwYrLBxIh6sh/
jfWIenw2ipRJJEHk64wBpQIKCpTPgloB8n8u2TbVqbrDefBanajPWWstOPw51YdW
2GSYqbRhIxQnin7WYztBlboIaRxehsftLeShWGokb0yOW5+4pqrw7w7vxv2d/uSl
fZx3MqHAesyqNGtcwOuf2tYr/NJZAaXawY3LfNJ4r49K/NwPTlI=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFEjCCA/qgAwIBAgIDMNypMA0GCSqGSIb3DQEBCwUAMIHPMQswCQYDVQQGEwJV
UzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UE
ChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjE6MDgGA1UECxMxaHR0cDov
L2NlcnRpZmljYXRlcy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5LzE2MDQG
A1UEAxMtU3RhcmZpZWxkIFNlcnZpY2VzIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
aXR5MB4XDTE0MDEwMTA3MDAwMFoXDTMxMDUzMDA3MDAwMFowgZgxCzAJBgNVBAYT
AlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYD
VQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTswOQYDVQQDEzJTdGFy
ZmllbGQgU2VydmljZXMgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANUMOsQq+U7i9b4Zl1+OiFOx
Hz/Lz58gE20pOsgPfTz3a3Y4Y9k2YKibXlwAgLIvWX/2h/klQ4bnaRtSmpDhcePY
LQ1Ob/bISdm28xpWriu2dBTrz/sm4xq6HZYuajtYlIlHVv8loJNwU4PahHQUw2ee
BGg6345AWh1KTs9DkTvnVtYAcMtS7nt9rjrnvDH5RfbCYM8TWQIrgMw0R9+53pBl
bQLPLJGmpufehRhJfGZOozptqbXuNC66DQO4M99H67FrjSXZm86B0UVGMpZwh94C
DklDhbZsc7tk6mFBrMnUVN+HL8cisibMn1lUaJ/8viovxFUcdUBgF4UCVTmLfwUC
AwEAAaOCASowggEmMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0G
A1UdDgQWBBScXwDfqgHXMCs4iKK4bUqc8hGRgzAfBgNVHSMEGDAWgBS0xn8aQ8yb
dV0vxEvyi5gQ6fFREDA6BggrBgEFBQcBAQQuMCwwKgYIKwYBBQUHMAGGHmh0dHA6
Ly9vY3NwLnN0YXJmaWVsZHRlY2guY29tLzA5BgNVHR8EMjAwMC6gLKAqhihodHRw
Oi8vY3JsLnN0YXJmaWVsZHRlY2guY29tL3Nmc3Jvb3QuY3JsMEwGA1UdIARFMEMw
QQYEVR0gADA5MDcGCCsGAQUFBwIBFitodHRwczovL2NlcnRzLnN0YXJmaWVsZHRl
Y2guY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAecaCOnFoOQtq5
dahqXiw8/d0pyrENYU07IixPbrm2Yq8SLFSeddBjqSPX5rVDjZXxoIakM9B75F2h
Yy0kBHyNyTERJN0GKEmjhXt8mvYKBw/sKf/WRiyxFwAn5oCnHSQf8KW8Jib4WBAS
SrqfnGSfL56QDKsh+28PuLLOtaxxy6mYgroHnjaX2pTvoKB497Gxl+vYbneVIIlF
oxXd/lwKyCmTaSu3sO0nvRIbtuk2JM28xbk7ESqWi19y1ief+aMd+8bB4Zljs4sX
x9L+ysaDkhndEAcFIU296RU3UXszEzfYcHiyKJsGIabXW+UPPayt3fFkc5jbbUrM
Qe7OXD6q
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIESTCCAzGgAwIBAgITBntQXCplJ7wevi2i0ZmY7bibLDANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMTIyMjQzNFoXDTQwMTAyMTIyMjQzNFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ
cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5
blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm
B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw
0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG
KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW
dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NybC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow
CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQAfsaEKwn17DjAbi/Die0etn+PE
gfY/I6s8NLWkxGAOUfW2o+vVowNARRVjaIGdrhAfeWHkZI6q2pI0x/IJYmymmcWa
ZaW/2R7DvQDtxCkFkVaxUeHvENm6IyqVhf6Q5oN12kDSrJozzx7I7tHjhBK7V5Xo
TyS4NU4EhSyzGgj2x6axDd1hHRjblEpJ80LoiXlmUDzputBXyO5mkcrplcVvlIJi
WmKjrDn2zzKxDX5nwvkskpIjYlJcrQu4iCX1/YwZ1yNqF9LryjlilphHCACiHbhI
RnGfN8j8KLDVmWyTYMk8V+6j0LI4+4zFh2upqGMQHL3VFVFWBek6vCDWhB/b
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIESTCCAzGgAwIBAgITBn+UV4WH6Kx33rJTMlu8mYtWDTANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ
cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5
blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm
B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw
0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG
KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW
dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow
CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCFkr41u3nPo4FCHOTjY3NTOVI1
59Gt/a6ZiqyJEi+752+a1U5y6iAwYfmXss2lJwJFqMp2PphKg5625kXg8kP2CN5t
6G7bMQcT8C8xDZNtYTd7WPD8UZiRKAJPBXa30/AbwuZe0GaFEQ8ugcYQgSn+IGBI
8/LwhBNTZTUVEWuCUUBVV18YtbAiPq3yXqMB48Oz+ctBWuZSkbvkNodPLamkB2g1
upRyzQ7qDn1X8nn8N8V7YJ6y68AtkHcNSRAnpTitxBKjtKPISLMVCx7i4hncxHZS
yLyKQXhw2W2Xs0qLeC1etA+jTGDK4UfLeC0SF7FSi8o5LL21L8IzApar2pR/
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICuzCCAmGgAwIBAgITBt5lU/RxKhgxLf2itIRtGzb3bjAKBggqhkjOPQQDAjA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSAzMB4XDTE4MDcxNjIyMDYyN1oXDTI4MDcxNjIyMDYyN1owRjELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENBIDNC
MQ8wDQYDVQQDEwZBbWF6b24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT54+5s
DVFTJ1ViZmj4Q6YZNDtTW9XnMo7GuR23TEgWcUWnqchC1tJ2vUEMJU9SJH3yWWeN
p8rxiiEaiURj27/vo4IBOTCCATUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
Af8EBAMCAYYwHQYDVR0OBBYEFK5cgP9Cl8nDoJtlCwTOnnF/Ps5aMB8GA1UdIwQY
MBaAFKu229cGnjesMIYHkXDHnMQZsXjAMHsGCCsGAQUFBwEBBG8wbTAvBggrBgEF
BQcwAYYjaHR0cDovL29jc3Aucm9vdGNhMy5hbWF6b250cnVzdC5jb20wOgYIKwYB
BQUHMAKGLmh0dHA6Ly9jcnQucm9vdGNhMy5hbWF6b250cnVzdC5jb20vcm9vdGNh
My5jZXIwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5yb290Y2EzLmFtYXpv
bnRydXN0LmNvbS9yb290Y2EzLmNybDARBgNVHSAECjAIMAYGBFUdIAAwCgYIKoZI
zj0EAwIDSAAwRQIhALhzrminJQeFNEOGC9JLWzlynT+3uBd6flr+oC+GiB97AiAv
2QsQjxOisNt7+i3DWrPWZ5qKcadzhUIpap5YnGmRcg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4
GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbF
NpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwM
zE4MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzET
MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQY
JKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2Ec
WtiHL8RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUh
hB5uzsTgHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL
0gRgykmmKPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65
TpjoWc4zdQQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rU
AVSNECMWEZXriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCA
wEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFI/wS3+oLkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNv
AUKr+yAzv95ZURUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8
dEe3jgr25sbwMpjjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw
8lo/s7awlOqzJCK6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0
095MJ6RMG3NzdvQXmcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVE
TI53O9zJrlAGomecsMx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02
JQZR7rkpeDMdmztcpHWD9f
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAwTDE
gMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2
JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcNM
zQxMjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
NjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCAiI
wDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQ
ssgrRIxutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuT
ToVBu1kZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqKGoC3GYEOfsSK
vGRMIRxDaNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n
16qIfKtJwLnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoSB239jLKJz9
CgYXfIWHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+azayOeSsJ
Da38O+2HBNXk7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiW
m05OWgtH8wY2SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4
UoQSwC+n+7o/hbguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUdnjqGBQ
Ce24DWJfncBZ4nWUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFl
WQaYw55PfWzjMpYrZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQUigAZ
cIN5kZeR1BonvzceMgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjA
PBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToD
AfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFA
AOCAgEAgyXt6NH9lVLNnsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcW
c+ZfwFSY1XS+wc3iEZGtIxg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKP
rmzU+sQghoefEQzd5Mr6155wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waN
rlU/yDXNOd8v9EDERm8tLjvUYAGm0CuiVdjaExUd1URhxN25mW7xocBFymFe944
Hn+Xds+qkxV/ZoVqW/hpvvfcDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl
+68KnyBr3TsTjxKM4kEaSHpzoHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU
3/gKbaKxCXcPu9czc8FB10jZpnOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTO
wY3WzvUy2MmeFe8nI+z1TIvWfspA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsVi
VO6LAUP5MSeGbEYNNVMnbrt9x+vJJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9
x8jvOOJckvB595yEunQtYQEgfn7R8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDf
LRVpOoERIyNiwmcUVhAn21klJwGW45hpxbqCo8YLoRT5s1gLXCmeDBVrJpBA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFWjCCA0KgAwIBAgISEdK7udcjGJ5AXwqdLdDfJWfRMA0GCSqGSIb3DQEBDAU
AMEYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRwwGg
YDVQQDExNHbG9iYWxTaWduIFJvb3QgUjQ2MB4XDTE5MDMyMDAwMDAwMFoXDTQ2M
DMyMDAwMDAwMFowRjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
bnYtc2ExHDAaBgNVBAMTE0dsb2JhbFNpZ24gUm9vdCBSNDYwggIiMA0GCSqGSIb
3DQEBAQUAA4ICDwAwggIKAoICAQCsrHQy6LNl5brtQyYdpokNRbopiLKkHWPd08
EsCVeJOaFV6Wc0dwxu5FUdUiXSE2te4R2pt32JMl8Nnp8semNgQB+msLZ4j5lUl
ghYruQGvGIFAha/r6gjA7aUD7xubMLL1aa7DOn2wQL7Id5m3RerdELv8HQvJfTq
a1VbkNud316HCkD7rRlr+/fKYIje2sGP1q7Vf9Q8g+7XFkyDRTNrJ9CG0Bwta/O
rffGFqfUo0q3v84RLHIf8E6M6cqJaESvWJ3En7YEtbWaBkoe0G1h6zD8K+kZPT
Xhc+CtI4wSEy132tGqzZfxCnlEmIyDLPRT5ge1lFgBPGmSXZgjPjHvjK8Cd+RTy
G/FWaha/LIWFzXg4mutCagI0GIMXTpRW+LaCtfOW3T3zvn8gdz57GSNrLNRyc0N
XfeD412lPFzYE+cCQYDdF3uYM2HSNrpyibXRdQr4G9dlkbgIQrImwTDsHTUB+JM
WKmIJ5jqSngiCNI/onccnfxkF0oE32kRbcRoxfKWMxWXEM2G/CtjJ9++ZdU6Z+F
fy7dXxd7Pj2Fxzsx2sZy/N78CsHpdlseVR2bJ0cpm4O6XkMqCNqo98bMDGfsVR7
/mrLZqrcZdCinkqaByFrgY/bxFn63iLABJzjqls2k+g9vXqhnQt2sQvHnf3PmKg
Gwvgqo6GDoLclcqUC4wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQ
H/BAUwAwEB/zAdBgNVHQ4EFgQUA1yrc4GHqMywptWU4jaWSf8FmSwwDQYJKoZIh
vcNAQEMBQADggIBAHx47PYCLLtbfpIrXTncvtgdokIzTfnvpCo7RGkerNlFo048
p9gkUbJUHJNOxO97k4VgJuoJSOD1u8fpaNK7ajFxzHmuEajwmf3lH7wvqMxX63b
EIaZHU1VNaL8FpO7XJqti2kM3S+LGteWygxk6x9PbTZ4IevPuzz5i+6zoYMzRx6
Fcg0XERczzF2sUyQQCPtIkpnnpHs6i58FZFZ8d4kuaPp92CC1r2LpXFNqD6v6MV
enQTqnMdzGxRBF6XLE+0xRFFRhiJBPSy03OXIPBNvIQtQ6IbbjhVp+J3pZmOUdk
LG5NrmJ7v2B0GbhWrJKsFjLtrWhV/pi60zTe9Mlhww6G9kuEYO4Ne7UyWHmRVSy
BQ7N0H3qqJZ4d16GLuc1CLgSkZoNNiTW2bKg2SnkheCLQQrzRQDGQob4Ez8pn7f
XwgNNgyYMqIgXQBztSvwyeqiv5u+YfjyW6hY0XHgL+XVAEV8/+LbzvXMAaq7afJ
Mbfc2hIkCwU9D9SGuTSyxTDYWnP4vkYxboznxSjBF25cfe1lNj2M8FawTSLfJvd
kzrnE6JwYZ+vj+vYxXX4M2bUdGc6N3ec592kD3ZDZopD8p/7DEJ4Y9HiD2971KE
9dJeFt0g5QdYg/NA6s/rob8SKunE3vouXsXgxT7PntgMTzlSdriVZzH81Xwj3QE
UxeCp6
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICCzCCAZGgAwIBAgISEdK7ujNu1LzmJGjFDYQdmOhDMAoGCCqGSM49BAMDME
YxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRwwGgYD
VQQDExNHbG9iYWxTaWduIFJvb3QgRTQ2MB4XDTE5MDMyMDAwMDAwMFoXDTQ2MD
MyMDAwMDAwMFowRjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
bnYtc2ExHDAaBgNVBAMTE0dsb2JhbFNpZ24gUm9vdCBFNDYwdjAQBgcqhkjOPQ
IBBgUrgQQAIgNiAAScDrHPt+ieUnd1NPqlRqetMhkytAepJ8qUuwzSChDH2omw
lwxwEwkBjtjqR+q+soArzfwoDdusvKSGN+1wCAB16pMLey5SnCNoIwZD7JIvU4
Tb+0cUB+hflGddyXqBPCCjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBQxCpCPtsad0kRLgLWi5h+xEk8blTAKBggqhkjOPQ
QDAwNoADBlAjEA31SQ7Zvvi5QCkxeCmb6zniz2C5GMn0oUsfZkvLtoURMMA/cV
i4RguYv/Uo7njLwcAjA8+RHUjE7AwWHCFUyqqx0LMV87HOIAl0Qx5v5zli/alt
P+CAezNIm8BZ/3Hobui3A=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICNDCCAbugAwIBAgIQdlP+urId2CfpaRai64G+WDAKBggqhkjOPQQDAzBcMQsw
CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMp
R2xvYmFsU2lnbiBDbGllbnQgQXV0aGVudGljYXRpb24gUm9vdCBFNDUwHhcNMjAw
MzE4MDAwMDAwWhcNNDUwMzE4MDAwMDAwWjBcMQswCQYDVQQGEwJCRTEZMBcGA1UE
ChMQR2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBDbGllbnQg
QXV0aGVudGljYXRpb24gUm9vdCBFNDUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATM
zLQ6uxpN+J2RxHeB7RZ/AxF/uOlwhEiWQQmDYF30JJMqMh5eB/tHpIcqJNhXjFzZ
qN8ReH+2RNXdr9UB2SY0X30xyMHu49a5/o+TAnCib2A7GXO1i3QKe51CF7wtPqej
QjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS1
g9ZwBorGnYaCd9WpBWU2E/HGSDAKBggqhkjOPQQDAwNnADBkAjBmpdF/fTQJFg4O
++53h4FKndiAh6BkaMtftnRYrMuymOKSEoktHT2xVGj4kvGNTkoCMBRVMnt2ZnSR
ayTUWpTi5WqA9np9zULzWHhjwekCe1TdHAEVncu/BBhVQCT6IvLZXg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFhDCCA2ygAwIBAgIQdlP+ufXH2+qLpHjUPj1r9jANBgkqhkiG9w0BAQwFADBc
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEyMDAGA1UE
AxMpR2xvYmFsU2lnbiBDbGllbnQgQXV0aGVudGljYXRpb24gUm9vdCBSNDUwHhcN
MjAwMzE4MDAwMDAwWhcNNDUwMzE4MDAwMDAwWjBcMQswCQYDVQQGEwJCRTEZMBcG
A1UEChMQR2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBDbGll
bnQgQXV0aGVudGljYXRpb24gUm9vdCBSNDUwggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQC+PrPi5LejQfhLmafaJmRr7a5Jg1F9bGDgnwvvOzrGtOhJO81t
pD4a1cpj6oN3AOJavVZsfIHB8NvmWtGbfW0ilijsmuO6t122ET7kesa4Gs8FIeko
N2X05Mmt5l0kL0iGPt9vFc4qsqVe3JUEkuV4JvjfXDXhv4ZTZZPLGJjj2ewyDcoK
8P9VeTgfXcyd7c4VtlifTlrgsdNJFBisCGDmz8N9Io5vJnlDcWbmR4+ENqZsAFJ2
tERfGu8ixAY2guMcVpo9UvdTBFEoINGzdC0tYjcpw2S45fqp9UCl/msU4f1zGZoh
I7HnzIajHCRItWw8IX8XU+lkriUXLPa7RJ44Z+9Ju1ty0xXdNRMfVUajRkmagvXP
fNHseYLOSCvdVvoZrSW4i7Zw14Kj5z2vbkGmPWDOeU9qxMkmOUS9Aa8dYXH29fE1
RiceAxngMXlscVHfw3ZlIpUe02tpvBBZGJFX4p9i6QuOtoeP4b+DzUpYshDd7uP8
DxwBYH72OGpccrl5Hd3XQ0cd7u3v/Mis+1Ihf4OGa7zu6XZ+VQt8nt5kREQUrqrn
JSowNhrxJ0Pwrf6jRddHyYF2IlzOjv3qDkEjuPjE9s1ljMt2mjytaoHEUb6tlA2M
F5EoASwechJUUUKk6ywPlFQsJTuTwzGGZIahbEjmvVBWzFCnashetvqFrwIDAQAB
o0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
dYKqG7azjRmP/Kl5zD8CmvRPy9kwDQYJKoZIhvcNAQEMBQADggIBAAFMXi+4f3I1
vLUYMIB9N3yRb3r0PK0gVhu4qTP3/qhcVFg5VTwz0Hq5NPyNVg3uAaYnG3EvtZp3
RYcE2I9bA3IDOSQdD3iQxcb1+H/6kKkiGw1nxrZSUPSdqOmgxHV6k9qxpWrtDEfO
oE6qcrTE5593kWX2awznDQdhCoevRhDV1ACrtbruRdFn5vd4n/l6wsennGwLXQ7F
yz/6I9G7n+o1Asg3NUEfmt0cRLqASoDZTgmV0j6yMJI0nO2dID8TDec2vQpRDMNq
V4rp2V2votwv1Za8xwjov6IV61QzYeVtzz31iZDiTY+cQL8Ug/KkNnol3njRCY2e
hQevcgRUIV0n7eVCEcs61mOs79L7fWrKhIHjCjJbkMDEjZKsCEsK39dW3NtmjHJe
PchOl6vLAaC2mLNXgDHvEU5AgmILem7K9SV7Wf/jvp/+/OpA6RogYKyGS6DBqUqx
qtTyM/4TObvvrhf5NssQ+3e64ulbA4fxaNzHlhVZ8jhUB0//AtQ48HBooCemDmQR
Kom2nr2CykmaRxG8u5h200NwxYhZ/M7nyxAhelShHb3N9+FOsxct6yTGx0pc2pgj
i7Jl0l/HfPkqK6VeDVBy1a7c+0iLhWcyQIF+CvIJTXicyU1ozvrhsfzZQf7mCfEi
ksRCXNTngVc4/6oai4r3z4f34t95em4E
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICIjCCAamgAwIBAgIQdlP+rhgmQ29p9RzCdxbyXjAKBggqhkjOPQQDAzBTMQsw
CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMg
R2xvYmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9vdCBFNDUwHhcNMjAwMzE4MDAwMDAw
WhcNNDUwMzE4MDAwMDAwWjBTMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
U2lnbiBudi1zYTEpMCcGA1UEAxMgR2xvYmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9v
dCBFNDUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR2GW0DtfWEI6syai5h3YQlL+/o
eSeJg8ODdfO2eGoIbaKtISoCkAbsmkCceoaRuViFyCiaLgv34nap37K9qcPpKRl5
CLJQ0MLFnQphDONdNwZKXP6EvcCAhPpLVSPg4j6jQjBAMA4GA1UdDwEB/wQEAwIB
hjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSnn93TVM3b+Gy/JmwO5Ndbb4DM
QjAKBggqhkjOPQQDAwNnADBkAjBsjFa2xTeuLZAreO2xHkYI0sNKKO94GQiOJDRG
T4dxYV+pEUpvMqsc0VJ7qjrq5ZoCMFUrdy/O+D+baEra16hLRQ1+smv2bNqxFeK8
SBl3i1fBXRTXQQDMJlLQILgZT5bnmg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFcjCCA1qgAwIBAgIQdlP+rHVGSJP15ddKSDpO+DANBgkqhkiG9w0BAQwFADBT
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UE
AxMgR2xvYmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9vdCBSNDUwHhcNMjAwMzE4MDAw
MDAwWhcNNDUwMzE4MDAwMDAwWjBTMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
YmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xvYmFsU2lnbiBDb2RlIFNpZ25pbmcg
Um9vdCBSNDUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2LcUw3Xro
q5A9A3KwOkuZFmGy5f+lZx03HOV+7JODqoT1o0ObmEWKuGNXXZsAiAQl6fhokkuC
2EvJSgPzqH9qj4phJ72hRND99T8iwqNPkY2zBbIogpFd+1mIBQuXBsKY+CynMyTu
UDpBzPCgsHsdTdKoWDiW6d/5G5G7ixAs0sdDHaIJdKGAr3vmMwoMWWuOvPSrWpd7
f65V+4TwgP6ETNfiur3EdaFvvWEQdESymAfidKv/aNxsJj7pH+XgBIetMNMMjQN8
VbgWcFwkeCAl62dniKu6TjSYa3AR3jjK1L6hwJzh3x4CAdg74WdDhLbP/HS3L4Sj
v7oJNz1nbLFFXBlhq0GD9awd63cNRkdzzr+9lZXtnSuIEP76WOinV+Gzz6ha6Qcl
mxLEnoByPZPcjJTfO0TmJoD80sMD8IwM0kXWLuePmJ7mBO5Cbmd+QhZxYucE+WDG
ZKG2nIEhTivGbWiUhsaZdHNnMXqR8tSMeW58prt+Rm9NxYUSK8+aIkQIqIU3zgdh
VwYXEiTAxDFzoZg1V0d+EDpF2S2kUZCYqaAHN8RlGqocaxZ396eX7D8ZMJlvMfvq
QLLn0sT6ydDwUHZ0WfqNbRcyvvjpfgP054d1mtRKkSyFAxMCK0KA8olqNs/ITKDO
nvjLja0Wp9Pe1ZsYp8aSOvGCY/EuDiRk3wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMC
AYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUHwC/RoAK/Hg5t6W0Q9lWULvO
ljswDQYJKoZIhvcNAQEMBQADggIBAF4runSXNERfdkgoQIST7gFu6aGz1oAl5nvk
vAmRPQ/8dq3X1DAgu49g0JHWHPKc73gaK5QyAsEkllJSAtDz0fzymzlumeEfjkNB
fZoeW8ldmoT8JuaH83RyJq2kG9k9O2pSoDwJHi8ee7MztEXH96yxr5NgrXauuLIV
eOuDauv/20arJOXuAvqQH1nAL13Wt12kXBC3clP4QU7M+ngaJUrK/oViQ2HDtDeq
gdL01joPvY1ZfjBH3itr5yFQM1/UZ5vUuGefPCeZA/+FQ45zEsogzehh1bFm3BfW
OW0P288jN6GCiU4caz/WoM2qB50+Qiaq1wzu+ke/GlJ+0XWB08mKYhdtT4igIaAm
Pq9t2WIwH+mYKK5ujdWOTHJmk4CNKuNVx2BnkEJWXCJRD7PcTjnuTd3ZHXgQVDtu
0JdvA7UesiNzxhKymmTQ/JWFJKj/36Gw3JFArt8JM6u53ZK38cyRdDtp62eXG5C/
58egb3G7V7+3j1rtekBqFs2AhC0v4QLUJJRDsxX8DCsb/XFv/Mu8dRc6XoPSybMv
G9WcjX9U/n5+5Fajh6ed4VlSlEGPbVu+hpWa/xp23UDSUUpwtB8zYyN3P+wnHlnk
CIftNIJKDz/+oB3B9WdzRYZ49Kop6SeHxhnbxhMUwzlJh02gl+BlE/Wdd1bp2rNY
xzrywM2C
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICLDCCAbGgAwIBAgIQdlP+sK9LdZCiGuSi1fJ2tTAKBggqhkjOPQQDAzBXMQsw
CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEtMCsGA1UEAxMk
R2xvYmFsU2lnbiBEb2N1bWVudCBTaWduaW5nIFJvb3QgRTQ1MB4XDTIwMDMxODAw
MDAwMFoXDTQ1MDMxODAwMDAwMFowVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEds
b2JhbFNpZ24gbnYtc2ExLTArBgNVBAMTJEdsb2JhbFNpZ24gRG9jdW1lbnQgU2ln
bmluZyBSb290IEU0NTB2MBAGByqGSM49AgEGBSuBBAAiA2IABIblQ9C7AGVe1koK
Y4WeRQ+GIzJQVUljapzO96/0fiD5gDJbbrDv8sekLPtqWZAGdrcXjA51RDqAfMjc
Aj3yzqGes0tyy8aM/cLJqoyuM1zqeUvcachWpDwoQXB0jmoaSKNCMEAwDgYDVR0P
AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGGZArQQ/xA823ra
bDpwJANg8eeOMAoGCCqGSM49BAMDA2kAMGYCMQCP9ck/sU7z99GdtLoPPQqXJxCT
8lB8IonajNTKqWMkJiqLY4JjVMc08NGeehgLp+oCMQCxNY9K8vsmBsHTDY9i0bDE
oF3pk9ZhxOGhuVyo9fFnXqIpN8JLxmdy/oyQ+SSAd7c=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFejCCA2KgAwIBAgIQdlP+sEyg1XHyFLOOLH8XQTANBgkqhkiG9w0BAQwFADBX
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEtMCsGA1UE
AxMkR2xvYmFsU2lnbiBEb2N1bWVudCBTaWduaW5nIFJvb3QgUjQ1MB4XDTIwMDMx
ODAwMDAwMFoXDTQ1MDMxODAwMDAwMFowVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
EEdsb2JhbFNpZ24gbnYtc2ExLTArBgNVBAMTJEdsb2JhbFNpZ24gRG9jdW1lbnQg
U2lnbmluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AKPQGKqmJaBoxSoYFVYt/dBLfaEecm4xsZ0STDc8LAzKutUukiBLkultAJxEbzgX
7xlg8skghJR6OwgNa0hl/NAeJPXU3NpHUphO342nitTllKh8siw4i+XSLZwAGTM3
irhsZWIblOjjm6R1ay2AGh0b5i+n7HHq6wQPsanAk1JhIC29UptoWDRLa0tbPm1y
1jjYlUGTTnn9T9W1/MiApVkIN+iyet62eQxB4PFg1i7y5KFN2BOrz45kW3zc5jEp
Hg2Qtjjo0PY6TTDHePklFWfhz3/3k5B/3kD6aYt9oENfRfnCS5d/UWEuC2LOYNoN
X3bMlJwd2IXs70V+vuoq0D8UjWkgfgxW/epp9KlEweatJ/9Ycah9LzufHn/ZcgXo
kSSAGtQheY4uWvr5j7AQKDCNquDyk9s9cVGrs553LgaAN4oLTg+YejcboM1JpUEQ
hMOfUG0vKI4u88+2x1SBbiychxEN7eP1hIsr/hSQu0ooVDRMZ/viKnN2JpFfx9o/
Np/aJy8nDcDHOf7b4/k2aYKAvfXB8aAz7od2H4gJft3oQbS+DxCkBuXt4Qh7JfdH
B7wqJQ8xOpGoqhMzkK8Op2DWgn1nTTQW4We7eeuCMEa0APhZuw78sxCRRSPY8TFC
BLFgZ6hjg7KsP5/3GBiETFGFZpoqHNLbKbmbG0Ma6jPtAgMBAAGjQjBAMA4GA1Ud
DwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQHQVdLz+EcFlPV
veuDbMyLKSGEvzANBgkqhkiG9w0BAQwFAAOCAgEAJJwyIaZykDsC3f64SqaO8Dew
W/8uP7Enbtl+nvSPX36/u4OFcMSKj0ZdxgpRKQLIxqBD/cICE/I6IZLdRpXDdLg8
VyIBhGhns1Beem4spPSj9QsM+VoNR4VFGk+bTNGokfOJqj5JqvWEsRe0S+ZeaRT9
RBsK/yDOCP70ZXKtxSJc3PKljMXcHWzb95anN2oaMLxrWTDjDUjxuGS5F5XG5J+D
prLujbvhniXMwFaoAQeRa6Qu6hPr2/FJb+U7OpYn/kRQ4Qw0qxgQwaZwieJSyB2/
YtY0guX+x5gAYRCAdyd8rF1yQrgiD3Ig9wpH0FUGVU/vZG2z/DrgoVZPZ8lFVMQT
IfurtfoxGlsGaU463x4gvCB/sCt0MtaodrM6PgseIETeh6b3UgsLjxT4MQOq6hHJ
2ZVGwIS72OsrLwpQxDgjf2+zv8Mnt/VMhwFzSQflwIyt7MeBQo/bXWsO2yHystfX
kieXNu3GS19zR7kMuA3cSUtFsr8xjuFVhCfpWBoxwg4m01/Ri70gXXHfl2Hd35XJ
4Msv20ScC3QKfRuKtE+MKJZM6CnLilxY8bg9bsLd2myyB6mr6NHR0niwPtPFaY13
54Rk+LFW8fsZ0Yhmbz0bZcglRTwfdDseHDjr8aMsUsG/6CH0Lo4yg58V6vQNo5RH
Rn7JhIJYRobXTF+4bZk=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICEzCCAZmgAwIBAgIQdlP+tWrI7k6Kxv5enjj16zAKBggqhkjOPQQDAzBKMQsw
CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEgMB4GA1UEAxMX
R2xvYmFsU2lnbiBJb1QgUm9vdCBFNjAwIBcNMjAwMzE4MDAwMDAwWhgPMjA2MDAz
MTgwMDAwMDBaMEoxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52
LXNhMSAwHgYDVQQDExdHbG9iYWxTaWduIElvVCBSb290IEU2MDB2MBAGByqGSM49
AgEGBSuBBAAiA2IABMqekQAPDaDOIzb3j1WPjK8mGxpr79Ep5hRQ18QA0nGZJfX1
DB0OcAnArxO0aQNIBKy0YWu2le+oSG7qvVDUdBKpojecHLpZfBdv/Np/weKlHWZu
g21MaOmCzsFwiCR9YKNCMEAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFIyT8B4s9dSMWR2/bMoVjzJkFveGMAoGCCqGSM49BAMDA2gA
MGUCMQCpCncG7eKtlGVfKrXiSdH3qJSGm0iL2+Lx+dfodRGZlL3Yn8ZOxejre094
2NN3VVYCMDdGNjlM7QKf8ZwXX6ey6bokVtXjsePehKrZAg2PVmQBYW6BNG2fTL0Q
TuvjV8A2VQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFYjCCA0qgAwIBAgIQdlP+s+o7ymRq611sfc77tjANBgkqhkiG9w0BAQwFADBK
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEgMB4GA1UE
AxMXR2xvYmFsU2lnbiBJb1QgUm9vdCBSNjAwIBcNMjAwMzE4MDAwMDAwWhgPMjA2
MDAzMTgwMDAwMDBaMEoxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
IG52LXNhMSAwHgYDVQQDExdHbG9iYWxTaWduIElvVCBSb290IFI2MDCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3t9w7POwmDeLxgKuglvptVLumhvR60
1yc3fN2bKRE0FhLqvpkoBU9sf12DG/w27QTE+FrKN6SJKX0AueWqrDokKVx2+am8
tl0DVkhKt2QQMWM+NJb2N82kX7KsZgh3Uot36y/pUnzCtKke9SSNn+Mxt+uyy9Kh
tyuYMKZPB6gtltGZFM+1ExZVFouQRxswjJZYfYTB49REfX9TxC0pamlmxixMH/Pq
LxvjcfLCEl6MpUBdd4WjYESJhxZQUby6lhGTCLFuMtqxnjZ9OSlBQKuEtK+8+jab
ofDWOPCaO5VLtNXceu4nQEIBHkf3z6NBveq4W0FYD4aCQkB29YuYLrvHKCjIXPX3
AH9oxWXNdbKcg5MZ5JlVSv/Ang4YctOizdfx0durq+fuWaurCSaiByHF1Pe8OJNQ
qd2lsnyZQkcA3/9Pw6R1AtvQm8aCAGR8IaA33U9ezcQTg/MYNSJBUZFu1YTDoZLc
IAh9spR0GOBgicXjDmmqNfhZ5x4bGXXieSD17Hm1ZOg4cMbssnOeyt8/XHFLi/Fe
O8zLCjgF5VITrtj8JnNBHd2uW1KVjRYfzc8/xp8ZBPDeal/B/RrLeH05B2yjtnVw
jo8A2N+IgOK5lU6Z3enPHaiibHUDK6Pd5aROm/+ZAnDpoOa8XTiNsMmJTc1oQ+rk
kfW6czMp8xORAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBTW8x33//JNLXKlDj0IEaURo4pqNjANBgkqhkiG9w0BAQwF
AAOCAgEAqwgG/A7j/mHFH6Vj1npdBaF9JQUYYhdqJw0JboY3votFL5P439oczcc/
QnFPcWXNw+ZSEzsV9GP0WAXO+mhBaOsD/ygcNXPUG5ZAnsDpO3F89/iARUkOEZXy
tMot2q9Vqz6VOKrJHymeT30kalVxLnQxilYAprlvkCC7nSH7fz1yBvLn5Isrd+zN
+JnYaXUqsllCnnzk7S6rJ8eCyRONo0YRAZtZvyim3ocRVUsxGrnVRf7PyeLtuC+C
Xj7Jd5VxXEqj0+y4k8QOh9XeTnCEm0ARJEDQu/frl1RQPwDCJKJfERpoyjC154Ft
SgB1kLOqUc20ZVsVSHI6ELmTM94XAC9g0j4G0CITsW29OVN/IwoBNYgpAwQGFbsO
E9skbIm9qo2c8Vg234sq2VkVDEGmfY55i6HiXXI/1ofIjXsApH/WeMHtQn5vKDRT
yXKlBwiy8sKKRCYDAmwkakh3LukprmUuzo0Ap43oodUaqPjJjFZxYQ1mIGnVQK5z
l9MRAO4er6WazCtP4JwzTctfch0jxpRGeueyp+LHaGNFSFbefO+aga9y9BF//CDZ
JmICXjEa/o6wogdtj/H3pf9fZzLh+yHP552N6osO8jzefkwqQZHQxgWTrq0NRnHG
bT4Myo/Dp/hZ4rOofDmmFOMgnM87f62CV/WJOXxaJi01FtZkCRE=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQdlP+qicdlUZd1vGe5biQCjAKBggqhkjOPQQDAzBSMQsw
CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UEAxMf
R2xvYmFsU2lnbiBTZWN1cmUgTWFpbCBSb290IEU0NTAeFw0yMDAzMTgwMDAwMDBa
Fw00NTAzMTgwMDAwMDBaMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxT
aWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFNlY3VyZSBNYWlsIFJvb3Qg
RTQ1MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+XmLgUc3iZY/RUlQfxomC5Myfi7A
wKcImsNuj5s+CyLsN1O3b4qwvCc3S22pRjvZH/+loUS7LXO/nkEHXFObUQg6Wrtv
OMcWkXjCShNpHYLfWi8AiJaiLhx0+Z1+ZjeKo0IwQDAOBgNVHQ8BAf8EBAMCAYYw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3xNei1/CQAL9VreUTLYe1aaxFJYw
CgYIKoZIzj0EAwMDaAAwZQIwE7C+13EgPuSrnM42En1fTB8qtWlFM1/TLVqy5IjH
3go2QjJ5naZruuH5RCp7isMSAjEAoGYcToedh8ntmUwbCu4tYMM3xx3NtXKw2cbv
vPL/P/BS3QjnqmR5w+RpV5EvpMt8
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFcDCCA1igAwIBAgIQdlP+qExQq5+NMrUdA49X3DANBgkqhkiG9w0BAQwFADBS
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
AxMfR2xvYmFsU2lnbiBTZWN1cmUgTWFpbCBSb290IFI0NTAeFw0yMDAzMTgwMDAw
MDBaFw00NTAzMTgwMDAwMDBaMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFNlY3VyZSBNYWlsIFJv
b3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3HnMbQb5bbvg
VgRsf+B1zC0FSehL3FTsW3eVcr9/Yp2FqYokUF9T5dt0b6QpWxMqCa2axS/C93Y7
oUVGqkPmJP4rsG8ycBlGWnkmL/w9fV9ky1fMYWGo2ZVu45Wgbn9HEhjW7wPJ+4r6
mr2CFalVd0sRT1nga8Nx8wzYVNWBaD4TuRUuh4o8RCc2YiRu+CwFcjBhvUKRI8Sd
JafZVJoUozGtgHkMp2NsmKOsV0czH2WW4dDSNdr5cfehpiW1QV3fPmDY0fafpfK4
zBOqj/mybuGDLZPdPoUa3eixXCYBy0mF/PzS1H+FYoZ0+cvsNSKiDDCPO6t561by
+kLz7fkfRYlAKa3qknTqUv1WtCvaou11wm6rzlKQS/be8EmPmkjUiBltRebMjLnd
ZGBgAkD4uc+8WOs9hbnGCtOcB2aPxxg5I0bhPB6jL1Bhkgs9K2zxo0c4V5GrDY/G
nU0E0iZSXOWl/SotFioBaeepfeE2t7Eqxdmxjb25i87Mi6E+C0jNUJU0xNgIWdhr
JvS+9dQiFwBXya6bBDAznwv731aiyW5Udtqxl2InWQ8RiiIbZJY/qPG3JEqNPFN8
bYN2PbImSHP1RBYBLQkqjhaWUNBzBl27IkiCTApGWj+A/1zy8pqsLAjg1urwEjiB
T6YQ7UarzBacC89kppkChURnRq39TecCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgGG
MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKCTFShu7o8IsjXGnmJ5dKexDit7
MA0GCSqGSIb3DQEBDAUAA4ICAQBFCvjRXKxigdAE17b/V1GJCwzL3iRlN/urnu1m
9OoMGWmJuBmxMFa02fb3vsaul8tF9hGMOjBkTMGfWcBGQggGR2QXeOCVBwbWjKKs
qdk/03tWT/zEhyjftisWI8CfH1vj1kReIk8jBIw1FrV5B4ZcL5fi9ghkptzbqIrj
pHt3DdEpkyggtFOjS05f3sH2dSP8Hzx4T3AxeC+iNVRxBKzIxG3D9pGx/s3uRG6B
9kDFPioBv6tMsQM/DRHkD9Ik4yKIm59fRz1RSeAJN34XITF2t2dxSChLJdcQ6J9h
WRbFPjJOHwzOo8wP5McRByIvOAjdW5frQmxZmpruetCd38XbCUMuCqoZPWvoajB6
V+a/s2o5qY/j8U9laLa9nyiPoRZaCVA6Mi4dL0QRQqYA5jGY/y2hD+akYFbPedey
Ttew+m4MVyPHzh+lsUxtGUmeDn9wj3E/WCifdd1h4Dq3Obbul9Q1UfuLSWDIPGau
l+6NJllXu3jwelAwCbBgqp9O3Mk+HjrcYpMzsDpUdG8sMUXRaxEyamh29j32ahNe
JJjn6h2az3iCB2D3TRDTgZpFjZ6vm9yAx0OylWikww7oCkcVv1Qz3AHn1aYec9h6
sr8vreNVMJ7fDkG84BH1oQyoIuHjAKNOcHyS4wTRekKKdZBZ45vRTKJkvXN5m2/y
s8H2PA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFcjCCA1qgAwIBAgIQdlP+uT3Z5+kmMqzWCr6sODANBgkqhkiG9w0BAQwFADBT
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UE
AxMgR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgUm9vdCBSNDUwHhcNMjAwMzE4MDAw
MDAwWhcNNDUwMzE4MDAwMDAwWjBTMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
YmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcg
Um9vdCBSNDUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC6dDPsJ9wS
OCEbxdNhKNZavE/fi8yRhEMkV7xkIbw7HB89T4ytB7fzxdcC6REUgpqqtJRyO3EN
Gu9oa4V5jq9m6liYDbrBfHnS/82zbzFF0AV0BAByaid+uDc/Oojtl4P1qzVND59Z
O/Uv31nFfKUydmCWyO3u+AR+GVFyqL9EQXq8ex47AJu8uuCWv5D+jZvDcosAEvgg
OmA498HMhYr7h3kuoSsg5sughZEjtsQoB1Qo3uwQMU+K8s0UHx7dVRzqKDFM+SFq
qM3zlmf6AUGbzQ8LaH+73vFD6hflsNxwIrNpNll0a8bliSp85QuBXas/j7jRdnLz
fKKp4pdBv8yMRf5hyfZsBwsABOgVI0+CKi3278P6ETZIodH9ejk6NF2jLA6bd1Ag
NEDdsQMxrV/pYodzlgNh95Sw2VxsT+cUxeHxew0jnM1wjB1q3kotiyq720IUBQeq
+xTcMdP2H2zLvmhmRHBNbRf5cesFc46RknXraFwe9kRhGCli3RdmiOwouklv2z53
/rkxH3UcGKKmR73Y7kiFO/2z4g8/KpjGmvqCb7GlpYYdWjr6pGx0D3dSYWp/hyne
OZuL7rNFYDAklxUSKoUwkyaslqYt6HBtC6kyrSybKAp2QvJVYVGYlN7t9sUXbzwV
ELAOrbDexRb0ZdHML1pWCM+ZxPBVkcIseQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMC
AYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELupt
st4wDQYJKoZIhvcNAQEMBQADggIBABZ8CmdKAzyTKj4cT0ZVsJqeiOHrU/1MVXmE
+Wy2n6kKtomrVAcUFkpJWvS4LoYUxH4ZifmHiLzsstKVjOAM+fKUZqaYVxuh39Fx
fYy1+HEC3RO2vvqwMcMsZ+saGA4aTdwszzFcYSipneNqLK5QSw460Gn7ijRE335L
jhqQCdox2sovpff0Nyw1DRpizTx7PFZ3ZZVclHNwn2EvaWQjHUx5B8IXfDrtqm1x
AxRiRcy3PlTYUXFC6juSQqUvVIGjsAxWWFa75JjuZscR+ahFF+JlKore4qjOxS32
9c6t8OMKCd1Te2ypbIZ+od42NQAPX4D9RbtxZkPURCzQuwFOmZ4+TeFeVh8FeoId
ssstpTO5OeXEt9pC4b3QlEKA+hiUO5NDqMiUOm1+nfxPoMLT5aWqECZvBiJb4AHi
Sr8Z5USesK2rGdLN60fEYoHs8MJ6jUz9wiW3vCxwjqqtUvQUPKp4HQTTydUlgqda
y4x8H1cCO4cbyNf5VBodyhpLJ7HiSu/nmkAUT6U8n9WjvpQ1nMLXPyjupBcrQ71k
p9ev6VPnp3cexRIbMeJLxn+eHO6jOpRQXaZQBlJeRQMrtADgwe3YDcGuu0kJgYJa
QkOvmWO4FNE8i93V8FTtcmfC9so+NYSHgA1SlVBB1rINGUAvthNN97Fg1HbFVzlu
WqJeCnnc
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFYDCCA0igAwIBAgIQCgFCgAAAAUUjyES1AAAAAjANBgkqhkiG9w0BAQsFADBK
MQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MScwJQYDVQQDEx5JZGVu
VHJ1c3QgQ29tbWVyY2lhbCBSb290IENBIDEwHhcNMTQwMTE2MTgxMjIzWhcNMzQw
MTE2MTgxMjIzWjBKMQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MScw
JQYDVQQDEx5JZGVuVHJ1c3QgQ29tbWVyY2lhbCBSb290IENBIDEwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQCnUBneP5k91DNG8W9RYYKyqU+PZ4ldhNlT
3Qwo2dfw/66VQ3KZ+bVdfIrBQuExUHTRgQ18zZshq0PirK1ehm7zCYofWjK9ouuU
+ehcCuz/mNKvcbO0U59Oh++SvL3sTzIwiEsXXlfEU8L2ApeN2WIrvyQfYo3fw7gp
S0l4PJNgiCL8mdo2yMKi1CxUAGc1bnO/AljwpN3lsKImesrgNqUZFvX9t++uP0D1
bVoE/c40yiTcdCMbXTMTEl3EASX2MN0CXZ/g1Ue9tOsbobtJSdifWwLziuQkkORi
T0/Br4sOdBeo0XKIanoBScy0RnnGF7HamB4HWfp1IYVl3ZBWzvurpWCdxJ35UrCL
vYf5jysjCiN2O/cz4ckA82n5S6LgTrx+kzmEB/dEcH7+B1rlsazRGMzyNeVJSQjK
Vsk9+w8YfYs7wRPCTY/JTw436R+hDmrfYi7LNQZReSzIJTj0+kuniVyc0uMNOYZK
dHzVWYfCP04MXFL0PfdSgvHqo6z9STQaKPNBiDoT7uje/5kdX7rL6B7yuVBgwDHT
c+XvvqDtMwt0viAgxGds8AgDelWAf0ZOlqf0Hj7h9tgJ4TNkK2PXMl6f+cB7D3hv
l7yTmvmcEpB4eoCHFddydJxVdHixuuFucAS6T6C6aMN7/zHwcz09lCqxC0EOoP5N
iGVreTO01wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB
/zAdBgNVHQ4EFgQU7UQZwNPwBovupHu+QucmVMiONnYwDQYJKoZIhvcNAQELBQAD
ggIBAA2ukDL2pkt8RHYZYR4nKM1eVO8lvOMIkPkp165oCOGUAFjvLi5+U1KMtlwH
6oi6mYtQlNeCgN9hCQCTrQ0U5s7B8jeUeLBfnLOic7iPBZM4zY0+sLj7wM+x8uwt
LRvM7Kqas6pgghstO8OEPVeKlh6cdbjTMM1gCIOQ045U8U1mwF10A0Cj7oV+wh93
nAbowacYXVKV7cndJZ5t+qntozo00Fl72u1Q8zW/7esUTTHHYPTa8Yec4kjixsU3
+wYQ+nVZZjFHKdp2mhzpgq7vmrlR94gjmmmVYjzlVYA211QC//G5Xc7UI2/YRYRK
W2XviQzdFKcgyxilJbQN+QHwotL0AMh0jqEqSI5l2xPE4iUXfeu+h1sXIFRRk0pT
AwvsXcoz7WL9RccvW9xYoIA55vrX/hMUpu09lEpCdNTDd1lzzY9GvlU47/rokTLq
l1gEIt44w8y8bckzOmoKaT+gyOpyj4xjhiO9bTyWnpXgSUyqorkqG5w2gXjtw+hG
4iZZRHUe2XWJUc0QhJ1hYMtd+ZciTY6Y5uN/9lu7rs3KSoFrXgvzUeF0K+l+J6fZ
mUlO+KWA2yUPHGNiiskzZ2s8EIPGrd6ozRaOjfAHN3Gf8qv8QfXBi+wAN10J5U6A
7/qxXDgGpRtK4dw4LTzcqx+QGtVKnO7RcGzM7vRX+Bi6hG6H
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF2DCCBMCgAwIBAgIRAOQnBJX2jJHW0Ox7SU6k3xwwDQYJKoZIhvcNAQELBQAw
fjELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMu
QS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEiMCAG
A1UEAxMZQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQTAeFw0xODA5MTEwOTI2NDda
Fw0yMzA5MTEwOTI2NDdaMHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQ
MA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMTEwLwYD
VQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUlNBMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA+Q/doyt9y9Aq/uxnhabnLhu6
d+Hj9a+k7PpKXZHEV0drGHdrdvL9k+Q9D8IWngtmw1aUnheDhc5W7/IW/QBi9SIJ
VOhlF05BueBPRpeqG8i4bmJeabFf2yoCfvxsyvNB2O3Q6Pw/YUjtsAMUHRAOSxng
u07shmX/NvNeZwILnYZVYf16OO3+4hkAt2+hUGJ1dDyg+sglkrRueiLH+B6h47Ld
kTGrKx0E/6VKBDfphaQzK/3i1lU0fBmkSmjHsqjTt8qhk4jrwZe8jPkd2SKEJHTH
BD1qqSmTzOu4W+H+XyWqNFjIwSNUnRuYEcM4nH49hmylD0CGfAL0XAJPKMuucZ8P
Osgz/hElNer8usVgPdl8GNWyqdN1eANyIso6wx/vLOUuqfqeLLZRRv2vA9bqYGjq
hRY2a4XpHsCz3cQk3IAqgUFtlD7I4MmBQQCeXr9/xQiYohgsQkCz+W84J0tOgPQ9
gUfgiHzqHM61dVxRLhwrfxpyKOcAtdF0xtfkn60Hk7ZTNTX8N+TD9l0WviFz3pIK
+KBjaryWkmo++LxlVZve9Q2JJgT8JRqmJWnLwm3KfOJZX5es6+8uyLzXG1k8K8zy
GciTaydjGc/86Sb4ynGbf5P+NGeETpnr/LN4CTNwumamdu0bc+sapQ3EIhMglFYK
TixsTrH9z5wJuqIz7YcCAwEAAaOCAVEwggFNMBIGA1UdEwEB/wQIMAYBAf8CAQIw
HQYDVR0OBBYEFN0ECQei9Xp9UlMSkpXuOIAlDaZZMB8GA1UdIwQYMBaAFAh2zcsH
/yT2xc3tu5C84oQ3RnX3MA4GA1UdDwEB/wQEAwIBBjA2BgNVHR8ELzAtMCugKaAn
hiVodHRwOi8vc3NsY29tLmNybC5jZXJ0dW0ucGwvY3RuY2EuY3JsMHMGCCsGAQUF
BwEBBGcwZTApBggrBgEFBQcwAYYdaHR0cDovL3NzbGNvbS5vY3NwLWNlcnR1bS5j
b20wOAYIKwYBBQUHMAKGLGh0dHA6Ly9zc2xjb20ucmVwb3NpdG9yeS5jZXJ0dW0u
cGwvY3RuY2EuY2VyMDoGA1UdIAQzMDEwLwYEVR0gADAnMCUGCCsGAQUFBwIBFhlo
dHRwczovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0GCSqGSIb3DQEBCwUAA4IBAQAflZoj
VO6FwvPUb7npBI9Gfyz3MsCnQ6wHAO3gqUUt/Rfh7QBAyK+YrPXAGa0boJcwQGzs
W/ujk06MiWIbfPA6X6dCz1jKdWWcIky/dnuYk5wVgzOxDtxROId8lZwSaZQeAHh0
ftzABne6cC2HLNdoneO6ha1J849ktBUGg5LGl6RAk4ut8WeUtLlaZ1Q8qBvZBc/k
pPmIEgAGiCWF1F7u85NX1oH4LK739VFIq7ZiOnnb7C7yPxRWOsjZy6SiTyWo0Zur
LTAgUAcab/HxlB05g2PoH/1J0OgdRrJGgia9nJ3homhBSFFuevw1lvRU0rwrROVH
13eCpUqrX5czqyQR
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
y702dmPTKEdEfwhgLx0LxJr/Aw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
y702dmPTKEdEfwhgLx0LxJr/Aw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF2DCCBMCgAwIBAgIRAOQnBJX2jJHW0Ox7SU6k3xwwDQYJKoZIhvcNAQELBQAw
fjELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMu
QS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEiMCAG
A1UEAxMZQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQTAeFw0xODA5MTEwOTI2NDda
Fw0yMzA5MTEwOTI2NDdaMHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQ
MA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMTEwLwYD
VQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUlNBMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA+Q/doyt9y9Aq/uxnhabnLhu6
d+Hj9a+k7PpKXZHEV0drGHdrdvL9k+Q9D8IWngtmw1aUnheDhc5W7/IW/QBi9SIJ
VOhlF05BueBPRpeqG8i4bmJeabFf2yoCfvxsyvNB2O3Q6Pw/YUjtsAMUHRAOSxng
u07shmX/NvNeZwILnYZVYf16OO3+4hkAt2+hUGJ1dDyg+sglkrRueiLH+B6h47Ld
kTGrKx0E/6VKBDfphaQzK/3i1lU0fBmkSmjHsqjTt8qhk4jrwZe8jPkd2SKEJHTH
BD1qqSmTzOu4W+H+XyWqNFjIwSNUnRuYEcM4nH49hmylD0CGfAL0XAJPKMuucZ8P
Osgz/hElNer8usVgPdl8GNWyqdN1eANyIso6wx/vLOUuqfqeLLZRRv2vA9bqYGjq
hRY2a4XpHsCz3cQk3IAqgUFtlD7I4MmBQQCeXr9/xQiYohgsQkCz+W84J0tOgPQ9
gUfgiHzqHM61dVxRLhwrfxpyKOcAtdF0xtfkn60Hk7ZTNTX8N+TD9l0WviFz3pIK
+KBjaryWkmo++LxlVZve9Q2JJgT8JRqmJWnLwm3KfOJZX5es6+8uyLzXG1k8K8zy
GciTaydjGc/86Sb4ynGbf5P+NGeETpnr/LN4CTNwumamdu0bc+sapQ3EIhMglFYK
TixsTrH9z5wJuqIz7YcCAwEAAaOCAVEwggFNMBIGA1UdEwEB/wQIMAYBAf8CAQIw
HQYDVR0OBBYEFN0ECQei9Xp9UlMSkpXuOIAlDaZZMB8GA1UdIwQYMBaAFAh2zcsH
/yT2xc3tu5C84oQ3RnX3MA4GA1UdDwEB/wQEAwIBBjA2BgNVHR8ELzAtMCugKaAn
hiVodHRwOi8vc3NsY29tLmNybC5jZXJ0dW0ucGwvY3RuY2EuY3JsMHMGCCsGAQUF
BwEBBGcwZTApBggrBgEFBQcwAYYdaHR0cDovL3NzbGNvbS5vY3NwLWNlcnR1bS5j
b20wOAYIKwYBBQUHMAKGLGh0dHA6Ly9zc2xjb20ucmVwb3NpdG9yeS5jZXJ0dW0u
cGwvY3RuY2EuY2VyMDoGA1UdIAQzMDEwLwYEVR0gADAnMCUGCCsGAQUFBwIBFhlo
dHRwczovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0GCSqGSIb3DQEBCwUAA4IBAQAflZoj
VO6FwvPUb7npBI9Gfyz3MsCnQ6wHAO3gqUUt/Rfh7QBAyK+YrPXAGa0boJcwQGzs
W/ujk06MiWIbfPA6X6dCz1jKdWWcIky/dnuYk5wVgzOxDtxROId8lZwSaZQeAHh0
ftzABne6cC2HLNdoneO6ha1J849ktBUGg5LGl6RAk4ut8WeUtLlaZ1Q8qBvZBc/k
pPmIEgAGiCWF1F7u85NX1oH4LK739VFIq7ZiOnnb7C7yPxRWOsjZy6SiTyWo0Zur
LTAgUAcab/HxlB05g2PoH/1J0OgdRrJGgia9nJ3homhBSFFuevw1lvRU0rwrROVH
13eCpUqrX5czqyQR
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG0zCCBLugAwIBAgIIUqgFJ65x5nUwDQYJKoZIhvcNAQELBQAwgYIxCzAJBgNV
BAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UE
CgwPU1NMIENvcnBvcmF0aW9uMTcwNQYDVQQDDC5TU0wuY29tIEVWIFJvb3QgQ2Vy
dGlmaWNhdGlvbiBBdXRob3JpdHkgUlNBIFIyMB4XDTE3MDQwNjE2NTczNFoXDTMy
MDQwNjE2NTczNFowcjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYD
VQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEuMCwGA1UEAwwlU1NMLmNv
bSBFViBTU0wgSW50ZXJtZWRpYXRlIENBIFJTQSBSMjCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBAIikWppdeTDzds/wo6dpNFVUs2waFmgOt6BsxB+CWlWQ
crbmSPZkO0QWJiyspQT9XUt01KzegBX7dtASCK+zh/sns4SxXegfvhNZDgns56uN
1Ccvg+ufQrKVkdXmkKWTRUZ7aG9v8kkP5kKFllVQlkaB3lQBaFxvv912tHO5YD3E
pe4cBE65MgogsaIOkICisBtSledLRIL8NAR1BpHN81+FYKqJTko1mR0ORhAeryNR
OMKh5bSg9rQ2DaoEdpB+TJir6KDMuzYsuPjoelk2mzcz2lo6t8L2v9LbX++Bc7Zc
78KPdRYkVL0Df0J4mZEkytC1a1h3dhGW07KjB2kiKRqYCebHDZdsOiGLSaf5kkeu
a5Q2e8p/lQmj+GYN/IEYLOeT5rT+l72rIraN46uG7fyRmKNFjggyx7zYcNoPIgIg
l8JIgnAqxkDLQsKTnAdGrySjKSsF1JF5LunHGhrDPibuvF+4Dy/WfB8uBSwzsjog
Aax0xKauYruDSmD4UFcvvswyZ67xz3Rr5yoGyS+mDJQqzCPZgkEfFWj2p1+TQBg7
eNAqE2OVxVMaZFMEyOxv/1O1N1oH8fc0QycStWlnhObFApHorL5phuPfwDgrstuY
aol16bJsITzRVGJsXdo1WQ5WL7fsMDPBpNONBpxC3XsyyWx1W8U6b2GA8ie8FOCT
AgMBAAGjggFaMIIBVjASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFPlg
u9Tj1TT2uPUGgCWnc9tGaaieMHcGCCsGAQUFBwEBBGswaTBFBggrBgEFBQcwAoY5
aHR0cDovL3d3dy5zc2wuY29tL2NlcnRzL1NTTGNvbS1Sb290Q0EtRVYtUlNBLTQw
OTYtUjIuY3J0MCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTARBgNV
HSAECjAIMAYGBFUdIAAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMEUG
A1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmxzLnNzbC5jb20vU1NMY29tLVJvb3RD
QS1FVi1SU0EtNDA5Ni1SMi5jcmwwHQYDVR0OBBYEFAoeWHuQwBtnsYkamLPZZ+KH
L3gJMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEABOt4gOLX6m7X
LCaxt5S/7Wo4+tzrnWZ/ePAJG8nKcGsQLwyO0pHbHF+m2IXPrrrtnVPpa1vX+ZsP
ZZryFI6uGuUSYQJI5mOx9pqg4YkSmEG6mC3+cVpy9Uo6UsR3jobZMaQCJyIax2eP
qNmzfjhLLcGTLSLN0IknKv1NWSMoWyIxN/K+votMi2jG0oaUzo5yrNIh1bUGY5py
CztH6m2nE83pCIr9oZh5xN2W0JZey2p96KS5y3Hewerg7eihOjuWMdzVaO58whKP
GLW/0rKdqmyKw22QL9arwgn5jQTxY4BSP+0ZxJEPHMZU9UlzuBsjao9w71AAFwGn
d61LKzRHJaFs3ll8Q5MWdGEwHJIIbTnqljLeJLNrzM9sWV0TUO7bLbZqIcDEgRTT
qdSb5m2+8GzExquQpSQ4pFUOBJCttHYho3ntbEd8ZPlQ9wEjRJT8s3/bg6vSmBoN
7bAdl+FbiWSuqLZ11KkqSwQ7v3S1qEPeg2AirbFw7ZNwJszUMpRL+KBWjcDuCkQj
WGPAv3sTS1BIM5id8oYkM+lSB/p72Q58brKOmPbTnXd/bJyte5FD0XMNmvwr1dtH
alwA4RAgVTjiuxSRapF/TlnetKLVnl9FKUiKy3dXGVbKNQA53HdK22yuZYiU+dN8
ClZ0xiuE3lrCuNYw2lBj0jHkwSk6+nA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF3jCCBMagAwIBAgIQYvgSo19SvXS3GNYQrEtHgzANBgkqhkiG9w0BAQsFADB+
MQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dpZXMgUy5B
LjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSIwIAYD
VQQDExlDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBMB4XDTE4MDkxMTA5MjgyMFoX
DTIzMDkxMTA5MjgyMFowgYIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQ
MA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMTcwNQYD
VQQDDC5TU0wuY29tIEVWIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUlNB
IFIyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjzZlQOHWTcDXtOlG
2mvqM0fNTPl9fb69LT3w23jhhqXZuglXaO1XPqDQCEGD5yhBJB/jchXQARr7XnAj
ssufOePPxU7Gkm0mxnu7s9onnQqG6YE3Bf7wcXHswxzpY6IXFJ3vG2fThVUCAtZJ
ycxa4bH3bzKfydQ7iEGonL3Lq9ttewkfokxykNorCPzPPFTOZw+oz12WGQvE43Lr
rdF9HSfvkusQv1vrO6/PgN3B0pYEW3p+pKk8OHakYo6gOV7qd89dAFmPZiw+B6Kj
BSYRaZfqhbcPlgtLyEDhULouisv3D5oi53+aNxPN8k0TayHRwMwi8qFG9kRpnMph
NQcAb9ZhCBHqurj26bNg5U257J8UZslXWNvNh2n4ioYSA0e/ZhN2rHd9NCSFg83X
qpyQGp8hLH94t2S42Oim9HizVcuE0jLEeK6jj2HdzghTreyI/BXkmg3mnxp3zkyP
uBQVPWKchjgGAGYS5Fl2WlPAApiiECtoRHuOec4zSnaqW4EWG7WK2NAAe15itAnW
hmMOpgWVSbooi4iTsjQc2KRVbrcc0N6ZVTsj9CLg+SlmJuwgUHfbSguPvuUCYHBB
XtSuUDkiFCbLsjtzdFVHB3mBOagwE0TlBIqulhMlQg+5U8Sb/M3kHN48+qvWBkof
Z6aYMBzdLNvcGJVXZsb/XItW9XcCAwEAAaOCAVEwggFNMBIGA1UdEwEB/wQIMAYB
Af8CAQIwHQYDVR0OBBYEFPlgu9Tj1TT2uPUGgCWnc9tGaaieMB8GA1UdIwQYMBaA
FAh2zcsH/yT2xc3tu5C84oQ3RnX3MA4GA1UdDwEB/wQEAwIBBjA2BgNVHR8ELzAt
MCugKaAnhiVodHRwOi8vc3NsY29tLmNybC5jZXJ0dW0ucGwvY3RuY2EuY3JsMHMG
CCsGAQUFBwEBBGcwZTApBggrBgEFBQcwAYYdaHR0cDovL3NzbGNvbS5vY3NwLWNl
cnR1bS5jb20wOAYIKwYBBQUHMAKGLGh0dHA6Ly9zc2xjb20ucmVwb3NpdG9yeS5j
ZXJ0dW0ucGwvY3RuY2EuY2VyMDoGA1UdIAQzMDEwLwYEVR0gADAnMCUGCCsGAQUF
BwIBFhlodHRwczovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0GCSqGSIb3DQEBCwUAA4IB
AQB3fEIlifCgb1DYzJtme4/TgnHi06tdHQmJyyzgqYqmnzfE+DBtuvHNVhalGHii
EvHuDXly28VCWb5aq4RKOkXrjuoCkSVtBf1Sys9ClK/Bqb7biO/58Ysoe6hwbikM
0lmi0c27gq2zMGi4/uZ8bzP+fpURtCHunmotpIMitYIz5nKmfLYEJALVDL/6ad8O
Lr+/dZTXKIDIYqdVjcGsvy0mQ12t+VRuJMRF+XTzy/LgDlr4SJjYZvWN7I4BxHyD
82YHj8XFnxgUiD47bn+ykoQa8WX4yV0xZeF+YN0lWLQCunFalTtqr4y6Mmc3pWBW
k5ojwldA7NjrZWoFiQ/blgLF
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF5jCCA86gAwIBAgIQEQDFvydYwZlp/Gjtcp381zANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQw
NzA0MDAwMDAwWhcNMjQwNzAzMjM1OTU5WjBNMQswCQYDVQQGEwJVUzEQMA4GA1UE
ChMHU1NMLmNvbTEUMBIGA1UECxMLd3d3LnNzbC5jb20xFjAUBgNVBAMTDVNTTC5j
b20gRFYgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAJEcVY7NR
2qmRMLzC17tObKov3Jf1AQLOfZRfCi26JM4lYzJoW7uMO6RSwBJeP6pSBYthSWLc
R+zd0bsQW5xKGITX51HYBH3daGWQEJIWVfL59cw3qhRsMQ5XP/IMZ15BOUxqGRVV
7NnCBBVcrWVhrEqSZbM6o61lMBU3sQQlYep/Ie3Ce6ca8oWfX5h4hrWtxuRCiBB4
EjxMB5KYOKJnQaOLEXaRhgr8cNHhzjl2KrKx/tCMtR/9pqy/+dOCKDiQWkg+hBoT
D/hGc/B3x7KfHAbdLJTPrRdJrFnSwMWwPcrWGIrrud3w5VxzXBjPAzQn7Dg/hpGB
NHEHBwKsLER3AgMBAAGjggGEMIIBgDAfBgNVHSMEGDAWgBRTeb9aqitKz1SA4dib
wJ3ysgNmyzAdBgNVHQ4EFgQURpr9/FFefFRTUuKZ47My75Maf1YwDgYDVR0PAQH/
BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMCEGA1UdIAQaMBgwDAYKKwYBBAGCqTABATAIBgZngQwBAgEwVQYD
VR0fBE4wTDBKoEigRoZEaHR0cDovL2NybC50cnVzdC1wcm92aWRlci5jb20vVVNF
UlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwgYAGCCsGAQUFBwEB
BHQwcjBEBggrBgEFBQcwAoY4aHR0cDovL2NydC50cnVzdC1wcm92aWRlci5jb20v
VVNFUlRydXN0UlNBQWRkVHJ1c3RDQS5jcnQwKgYIKwYBBQUHMAGGHmh0dHA6Ly9v
Y3NwLnRydXN0LXByb3ZpZGVyLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAB1RJZUdF
d05ZN1SYdTZsDj9Rq9De097SCCWi0E97Ehc2MRQag98VqlZPrC2WM9q+C7Z5MvcM
1njs15p55YRJbHjjECgiabKEPsx3xXH+oTb4kKzQjqMZV5CNC7K+5H4OaCtNcFEZ
E2vWRI9hunFjTfTJ9VrKjGIwcYz30VtdB1vtk0Jaf0lnC4H1GOAdw3IwJgbygOeu
ACY/1RH5U0ai2e9wWXsiADjBtHbiFPEzt5Cmu2wag9fPrX663Xs5TqjDNCPAgCLm
ijzyrCQmlCaug332cwnYI5dA0Oa/eIV6lYZTev143bZWs+A6dQhXDJUQzfSvPsQS
Pu/W3QAkw4vuZ97mVvgzK5LiDWps2N9Fw9b5Et4Op+cuy27I48fG3bRH0dROJwYs
w+MrMc5Sy/TOl9a5UUmtq2jEJbEv7xU5x1bvhaFfBtxoF36sLLuPf19Aev4n2Y46
Fou4Aup1eWVyS+XYKiaTGzxL5b4fbwhKItk8NptdrJ26YmdCl6cFNaabXHHak24W
I0cF4+u8ATOxkdFkuLyWusWzfmfIMHX1ZHD3giYavooNnupzxnju58Tpc9AsCgyL
rRxTbur5AscjOsHHfzeeTqflKtslTvJ9AvNkPLizR2cMk4+1h+6yDBHggsm0bZn0
AeY5kXGfjIimFcd00xvjkVn41em3We1sghs=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
MBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow
GAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj
YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQua
BtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe
3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4
YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZR
rOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm
ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQU
oBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v
QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29t
b2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUF
AAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q
GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz
Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2
G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi
l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3
smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFgTCCBGmgAwIBAgIQOXJEOvkit1HX02wQ3TE1lTANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBJlFzYOw9sI
s9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p7PbPwdzx07HWezcoEStH2jnG
vDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i6HTJGLSR1GJk23+jBvGIGGqQ
Ijy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+fmyc/xadGL1RjjWmp2bIcmfb
IWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9tyy29lTdyOcSOk2uTIq3XJq0
tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND8zLDU+/bqv50TmnHa4xgk97E
xwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt925H+nND5X4OpWaxKXwyhGNV
icQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/YgIoJk2KOtWbPJYjNhLixP6Q5
D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPtW//e5XOsIzstAL81VXQJSdhJ
WBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ51eHnlAfV1SoPv10Yy+xUGUJ
5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV4clXhB4PY9bpYrrWX1Uu6lzG
KAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB8jCB7zAfBgNVHSMEGDAWgBSg
EQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rID
ZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAG
BgRVHSAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29t
L0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggr
BgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUA
A4IBAQAYh1HcdCE9nIrgJ7cz0C7M7PDmy14R3iJvm3WOnnL+5Nb+qh+cli3vA0p+
rvSNb3I8QzvAP+u431yqqcau8vzY7qN7Q/aGNnwU4M309z/+3ri0ivCRlv79Q2R+
/czSAaF9ffgZGclCKxO/WIu6pKJmBHaIkU4MiRTOok3JMrO66BQavHHxW/BBC5gA
CiIDEOUMsfnNkjcZ7Tvx5Dq2+UUTJnWvu6rvP3t3O9LEApE9GQDTF1w52z97GA1F
zZOFli9d31kWTz9RvdVFGD/tSo7oBmF0Ixa1DVBzJ0RHfxBdiSprhTEUxOipakyA
vGp4z7h/jnZymQyd/teRCBaho1+V
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFujCCA6KgAwIBAgIJALtAHEP1Xk+wMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxHzAdBgNVBAMTFlN3aXNzU2ln
biBHb2xkIENBIC0gRzIwHhcNMDYxMDI1MDgzMDM1WhcNMzYxMDI1MDgzMDM1WjBF
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMR8wHQYDVQQDExZT
d2lzc1NpZ24gR29sZCBDQSAtIEcyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAr+TufoskDhJuqVAtFkQ7kpJcyrhdhJJCEyq8ZVeCQD5XJM1QiyUqt2/8
76LQwB8CJEoTlo8jE+YoWACjR8cGp4QjK7u9lit/VcyLwVcfDmJlD909Vopz2q5+
bbqBHH5CjCA12UNNhPqE21Is8w4ndwtrvxEvcnifLtg+5hg3Wipy+dpikJKVyh+c
6bM8K8vzARO/Ws/BtQpgvd21mWRTuKCWs2/iJneRjOBiEAKfNA+k1ZIzUd6+jbqE
emA8atufK+ze3gE/bk3lUIbLtK/tREDFylqM2tIrfKjuvqblCqoOpd8FUrdVxyJd
MmqXl2MT28nbeTZ7hTpKxVKJ+STnnXepgv9VHKVxaSvRAiTysybUa9oEVeXBCsdt
MDeQKuSeFDNeFhdVxVu1yzSJkvGdJo+hB9TGsnhQ2wwMC3wLjEHXuendjIj3o02y
MszYF9rNt85mndT9Xv+9lz4pded+p2JYryU0pUHHPbwNUMoDAw8IWh+Vc3hiv69y
FGkOpeUDDniOJihC8AcLYiAQZzlG+qkDzAQ4embvIIO1jEpWjpEA/I5cgt6IoMPi
aG59je883WX0XaxR7ySArqpWl2/5rX3aYT+YdzylkbYcjCbaZaIJbcHiVOO5ykxM
gI93e2CaHt+28kgeDrpOVG2Y4OGiGqJ3UM/EY5LsRxmd6+ZrzsECAwEAAaOBrDCB
qTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUWyV7
lqRlUX64OfPAeGZe6Drn8O4wHwYDVR0jBBgwFoAUWyV7lqRlUX64OfPAeGZe6Drn
8O4wRgYDVR0gBD8wPTA7BglghXQBWQECAQEwLjAsBggrBgEFBQcCARYgaHR0cDov
L3JlcG9zaXRvcnkuc3dpc3NzaWduLmNvbS8wDQYJKoZIhvcNAQEFBQADggIBACe6
45R88a7A3hfm5djV9VSwg/S7zV4Fe0+fdWavPOhWfvxyeDgD2StiGwC5+OlgzczO
UYrHUDFu4Up+GC9pWbY9ZIEr44OE5iKHjn3g7gKZYbge9LgriBIWhMIxkziWMaa5
O1M/wySTVltpkuzFwbs4AOPsF6m43Md8AYOfMke6UiI0HTJ6CVanfCU2qT1L2sCC
bwq7EsiHSycR+R4tx5M/nttfJmtS2S6K8RTGRI0Vqbe/vd6mGu6uLftIdxf+u+yv
GPUqUfA5hJeVbG4bwyvEdGB5JbAKJ9/fXtI5z0V9QkvfsywexcZdylU6oJxpmo/a
77KwPJ+HbBIrZXAVUjEaJM9vMSNQH4xPjyPDdEFjHFWoFN0+4FFQz/EbMFYOkrCC
hdiDyyJkvC24JdVUorgG6q2SpCSgwYa1ShNqR88uC1aVVMvOmttqtKay20EIhid3
92qgQmwLOM7XdVAyksLfKzAiSNDVQTglXaTpXZ/GlHXQRf0wl0OPkKsKx4ZzYEpp
Ld6leNcG2mqeSz53OiATIgHQv2ieY2BrNU0LbbqhPcCT4H8js1WtciVORvnSFu+w
ZMEBnunKoGqYDs/YYPIvSbjkQuE4NRb0yG5P94FW6LqjviOvrv1vA+ACOzB2+htt
Qc8Bsem4yWb02ybzOqR08kkkW8mw0FfB+j564ZfJ
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFwTCCA6mgAwIBAgIITrIAZwwDXU8wDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEjMCEGA1UEAxMaU3dpc3NTaWdu
IFBsYXRpbnVtIENBIC0gRzIwHhcNMDYxMDI1MDgzNjAwWhcNMzYxMDI1MDgzNjAw
WjBJMQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQD
ExpTd2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAMrfogLi2vj8Bxax3mCq3pZcZB/HL37PZ/pEQtZ2Y5Wu669y
IIpFR4ZieIbWIDkm9K6j/SPnpZy1IiEZtzeTIsBQnIJ71NUERFzLtMKfkr4k2Htn
IuJpX+UFeNSH2XFwMyVTtIc7KZAoNppVRDBopIOXfw0enHb/FZ1glwCNioUD7IC+
6ixuEFGSzH7VozPY1kneWCqv9hbrS3uQMpe5up1Y8fhXSQQeol0GcN1x2/ndi5ob
jM89o03Oy3z2u5yg+gnOI2Ky6Q0f4nIoj5+saCB9bzuohTEJfwvH6GXp43gOCWcw
izSC+13gzJ2BbWLuCB4ELE6b7P6pT1/9aXjvCR+htL/68++QHkwFix7qepF6w9fl
+zC8bBsQWJj3Gl/QKTIDE0ZNYWqFTFJ0LwYfexHihJfGmfNtf9dng34TaNhxKFrY
zt3oEBSa/m0jh26OWnA81Y0JAKeqvLAxN23IhBQeW71FYyBrS3SMvds6DsHPWhaP
pZjydomyExI7C3d3rLvlPClKknLKYRorXkzig3R3+jVIeoVNjZpTxN94ypeRSCtF
KwH3HBqi7Ri6Cr2D+m+8jVeTO9TUps4e8aCxzqv9KyiaTxvXw3LbpMS/XUz13XuW
ae5ogObnmLo2t/5u7Su9IPhlGdpVCX4l3P5hYnL5fhgC72O00Puv5TtjjGePAgMB
AAGjgawwgakwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFFCvzAeHFUdvOMW0ZdHelarp35zMMB8GA1UdIwQYMBaAFFCvzAeHFUdvOMW0
ZdHelarp35zMMEYGA1UdIAQ/MD0wOwYJYIV0AVkBAQEBMC4wLAYIKwYBBQUHAgEW
IGh0dHA6Ly9yZXBvc2l0b3J5LnN3aXNzc2lnbi5jb20vMA0GCSqGSIb3DQEBBQUA
A4ICAQAIhab1Fgz8RBrBY+D5VUYI/HAcQiiWjrfFwUF1TglxeeVtlspLpYhg0DB0
uMoI3LQwnkAHFmtllXcBrqS3NQuB2nEVqXQXOHtYyvkv+8Bldo1bAbl93oI9ZLi+
FHSjClTTLJUYFzX1UWs/j6KWYTl4a0vlpqD4U99REJNi54Av4tHgvI42Rncz7Lj7
jposiU0xEQ8mngS7twSNC/K5/FqdOxa3L8iYq/6KUFkuozv8KV2LwUvJ4ooTHbG/
u0IdUt1O2BReEMYxB+9xJ/cbOQncguqLs5WGXv312l0xpuAxtpTmREl0xRbl9x8D
YSjFyMsSoEJL+WuICI20MhjzdZ/EfwBPBZWcoxcCw7NTm6ogOSkrZvqdr16zktK1
puEa+S1BaYEUtLS17Yk9zvupnTVCRLEcFHOBzyoBNZox1S2PbYTfgE1X4z/FhHXa
icYwu+uPyyIIoK6q8QNsOktNCaUOcsZWayFCTiMlFGiudgp8DAdwZPmaL/YFOSbG
DI8Zf0NebvRbFS/bYV3mZy8/CJT5YLSYMdp08YSTcU1f+2BY0fvEwW2JorsgH51x
kcsymxM9Pn2SUjWskpSi0xjCfMfqr3YFFt1nJ8J+HAciIfNAChs0B0QTwoRqjt8Z
Wr9/6x3iGjjRXK9HkmuAtTClyY3YqzGBH9/CZjfTk6mFhnll0g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFvTCCA6WgAwIBAgIITxvUL1S7L0swDQYJKoZIhvcNAQEFBQAwRzELMAkGA1UE
BhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEhMB8GA1UEAxMYU3dpc3NTaWdu
IFNpbHZlciBDQSAtIEcyMB4XDTA2MTAyNTA4MzI0NloXDTM2MTAyNTA4MzI0Nlow
RzELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEhMB8GA1UEAxMY
U3dpc3NTaWduIFNpbHZlciBDQSAtIEcyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAxPGHf9N4Mfc4yfjDmUO8x/e8N+dOcbpLj6VzHVxumK4DV644N0Mv
Fz0fyM5oEMF4rhkDKxD6LHmD9ui5aLlV8gREpzn5/ASLHvGiTSf5YXu6t+WiE7br
YT7QbNHm+/pe7R20nqA1W6GSy/BJkv6FCgU+5tkL4k+73JU3/JHpMjUi0R86TieF
nbAVlDLaYQ1HTWBCrpJH6INaUFjpiou5XaHc3ZlKHzZnu0jkg7Y360g6rw9njxcH
6ATK72oxh9TAtvmUcXtnZLi2kUpCe2UuMGoM9ZDulebyzYLs2aFK7PayS+VFheZt
eJMELpyCbTapxDFkH4aDCyr0NQp4yVXPQbBH6TCfmb5hqAaEuSh6XzjZG6k4sIN/
c8HDO0gqgg8hm7jMqDXDhBuDsz6+pJVpATqJAHgE2cn0mRmrVn5bi4Y5FZGkECwJ
MoBgs5PAKrYYC51+jUnyEEp/+dVGLxmSo5mnJqy7jDzmDrxHB9xzUfFwZC8I+bRH
HTBsROopN4WSaGa8gzj+ezku01DwH/teYLappvonQfGbGHLy9YR0SslnxFSuSGTf
jNFusB3hB48IHpmccelM2KX3RxIfdNFRnobzwqIjQAtz20um53MGjMGg6cFZrEb6
5i/4z3GcRm25xBWNOHkDRUjvxF3XCO6HOSKGsg0PWEP3calILv3q1h8CAwEAAaOB
rDCBqTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
F6DNweRBtjpbO8tFnb0cwpj6hlgwHwYDVR0jBBgwFoAUF6DNweRBtjpbO8tFnb0c
wpj6hlgwRgYDVR0gBD8wPTA7BglghXQBWQEDAQEwLjAsBggrBgEFBQcCARYgaHR0
cDovL3JlcG9zaXRvcnkuc3dpc3NzaWduLmNvbS8wDQYJKoZIhvcNAQEFBQADggIB
AHPGgeAn0i0P4JUw4ppBf1AsX19iYamGamkYDHRJ1l2E6kFSGG9YrVBWIGrGvShp
WJHckRE1qTodvBqlYJ7YH39FkWnZfrt4csEGDyrOj4VwYaygzQu4OSlWhDJOhrs9
xCrZ1x9y7v5RoSJBsXECYxqCsGKrXlcSH9/L3XWgwF15kIwb4FDm3jH+mHtwX6WQ
2K34ArZv02DdQEsixT2tOnqfGhpHkXkzuoLcMmkDlm4fS/Bx/uNncqCxv1yL5PqZ
IseEuRuNI5c/7SXgz2W79WEE790eslpBIlqhn10s6FvJbakMDHiqYMZWjwFaDGi8
aRl5xB9+lwW/xekkUV7U1UtT7dkjWjYDZaPBA61BMPNGG4WQr2W11bHkFlt4dR2X
em1ZqSqPe97Dh4kQmUlzeMg9vVE1dCrV8X5pGyq7O70luJpaPXJhkGaH7gzWTdQR
dAtq/gsD/KNVV4n+SsuuWxcFyPKNIzFTONItaj+CuY0IavdeQXRuwxF+B6wpYJE/
OMpXEA29MC/HpeZBoNquBYeaoKRlbEwJDIm6uNO5wJOKMPqN5ZprFQFOZ6raYlY+
hAhm0sQ2fac+EPyI4NSA5QC9qvNOBqN6avlicuMJT+ubDgEj8Z+7fNzcbBGXJbLy
tGMU0gYqZ4yD9c7qB9iaah7s5Aq7KkzrCWA5zspi2C5u
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGuTCCBKGgAwIBAgIQAIEIODzAB3XEDG1za+MwizANBgkqhkiG9w0BAQsFADBF
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMR8wHQYDVQQDExZT
d2lzc1NpZ24gR29sZCBDQSAtIEcyMB4XDTE0MDkxNTE2MTYzN1oXDTM1MDMwNDE2
MTYzN1owTjELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEoMCYG
A1UEAxMfU3dpc3NTaWduIEVWIEdvbGQgQ0EgMjAxNCAtIEcyMjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAL+MVu10kh055MUIkpRaC7sfiuFQ4gAYFv4B
5LfsK6NSpTaJybYvrA/lr0JBE/xTsQl3Jrka60FgprSh9pXgE94UVoE2Qb4LiHEo
AIYyBQY0aA3nL9GEkT436uXs0tV2Veg6+6CgGRzgaoQtDu3hXWV5GOyNOAtlmzR4
md1JH6oFap9d3kVwJLExUI930Cwjzwt0XAcvjy8+fLheBanG5VFGnRrntRSWiRzY
QIjjAkBDTi+lj552h9aKzFvFEQ5NSiBmrGVk2wIlrh+AZe8NYnXrRBzv0Z5SODD4
jxyPkTAX7f9zkJ9s0yMVEmalWnfwXn4K4Rz3x7fmWeyxipUOhSkCAwEAAaOCApow
ggKWMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW
BBTu/UbK9ydekbxatueHzQr6VQomQjAfBgNVHSMEGDAWgBRbJXuWpGVRfrg588B4
Zl7oOufw7jCB/wYDVR0fBIH3MIH0MEegRaBDhkFodHRwOi8vY3JsLnN3aXNzc2ln
bi5uZXQvNUIyNTdCOTZBNDY1NTE3RUI4MzlGM0MwNzg2NjVFRTgzQUU3RjBFRTCB
qKCBpaCBooaBn2xkYXA6Ly9kaXJlY3Rvcnkuc3dpc3NzaWduLm5ldC9DTj01QjI1
N0I5NkE0NjU1MTdFQjgzOUYzQzA3ODY2NUVFODNBRTdGMEVFJTJDTz1Td2lzc1Np
Z24lMkNDPUNIP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RD
bGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDBaBgNVHSAEUzBRME8GBFUdIAAwRzBF
BggrBgEFBQcCARY5aHR0cDovL3JlcG9zaXRvcnkuc3dpc3NzaWduLmNvbS9Td2lz
c1NpZ24tR29sZC1DUC1DUFMucGRmMIHRBggrBgEFBQcBAQSBxDCBwTBkBggrBgEF
BQcwAoZYaHR0cDovL3N3aXNzc2lnbi5uZXQvY2dpLWJpbi9hdXRob3JpdHkvZG93
bmxvYWQvNUIyNTdCOTZBNDY1NTE3RUI4MzlGM0MwNzg2NjVFRTgzQUU3RjBFRTBZ
BggrBgEFBQcwAYZNaHR0cDovL2dvbGQtZXYtZzIub2NzcC5zd2lzc3NpZ24ubmV0
LzVCMjU3Qjk2QTQ2NTUxN0VCODM5RjNDMDc4NjY1RUU4M0FFN0YwRUUwDQYJKoZI
hvcNAQELBQADggIBACVxhUgwnsFZgEmC50cCMExcmvY9OQkPxcQbMMFCYvfvBFNz
65iu0MkXTo0jhaIe8wOOsv230q/zYJbTZOGbMpvUg5MRRIK9DCq3bDwAqN9bIjFw
wK1bODt260m9+4gLxJJdt2MH5LAglQ2J0123+RodYxvv3b+5k6/DZ19dJUgXrjbD
+0PWuO5+5DRangp3VELIRWjHAAnpmq3guORiLuVDS+PoinFp/CKEFRhgWIhp6sZd
yA/9egO+ZH+U7KzLaMuYRNHfJr2UrgQUEufsOM0WUqQXS8RzO7ZGW/argfyc4NdS
CivO97xZBroON0XaLOlTAAbubomhzz/K/Uv2S5T+I/AfYWCme7Vx/KyeA9if/eLA
jQNn5lIb1cXhompM2M+kLAGjNhdpQvUSkjAhKOkzoeezJEN+RXU4P5tOJxw03LtJ
VxmdQxQwgXOR0rBZT+9aFJSX1nIj7zWRnMwFu5w+gBaX1/5MuLP/ThJCckoVgb0o
nbFLRn6siH6dNE+gZ5VgiMWeDOkwlR1UMWGMNwoKNExoTKYwKnpuMfv4q7Fx4uI9
qVzGTL6yfW8+SRdxVFQa6K9hekBr2kZyAKBCqz+jpQq1EPCcvn4HiNx81Na++iqe
K+d2mfZxdEuAwFoZIcyk1aTWHHT1Cqzys00wlukvSmnXUBbGU5Vpwzjlj3N4
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGYDCCBEigAwIBAgIIOSskHWFEw1owDQYJKoZIhvcNAQEFBQAwRTELMAkGA1UE
BhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEfMB0GA1UEAxMWU3dpc3NTaWdu
IEdvbGQgQ0EgLSBHMjAeFw0wODA3MDcxNzI0MThaFw0yMzA3MDcxNzI0MThaMFMx
CzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxLTArBgNVBAMTJFN3
aXNzU2lnbiBQZXJzb25hbCBHb2xkIENBIDIwMDggLSBHMjCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAOM73Ly81W/YVyZ1q9DzFs62X24958JsP4RCAkGN
LIN+F1c1ENuKmRgxFsLT2Jj/VDz4Y+ZX5Xj6dRSJpjuOv/vzzMyF4xobXQAedKpb
nm3oV9oksohSWXMBJMXfSSpCrt/yW/xdmKa0s7nFbZozR7pWlh83RCYBTR+G0NjN
d/ls3Tgjsgl0DJwgXxUkC+gvtad/ETtSFs/YkjnQK+8TCz7mf4hmrXIe0ExWjjxv
huNjCQ6klBtO+48mtcTruGxcSE6gOAi0HLUYJzXBEtkhSlbpIFEonerWlB+xE3BG
dz4mdq34fxMz7NVLhp5V6hzDxmIfnD1HAWCrUSt+NpLvLZsCAwEAAaOCAkQwggJA
MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSu
eosV+CU+9BrvQ2slwKbhGjymqzAfBgNVHSMEGDAWgBRbJXuWpGVRfrg588B4Zl7o
Oufw7jCB/wYDVR0fBIH3MIH0MEegRaBDhkFodHRwOi8vY3JsLnN3aXNzc2lnbi5u
ZXQvNUIyNTdCOTZBNDY1NTE3RUI4MzlGM0MwNzg2NjVFRTgzQUU3RjBFRTCBqKCB
paCBooaBn2xkYXA6Ly9kaXJlY3Rvcnkuc3dpc3NzaWduLm5ldC9DTj01QjI1N0I5
NkE0NjU1MTdFQjgzOUYzQzA3ODY2NUVFODNBRTdGMEVFJTJDTz1Td2lzc1NpZ24l
MkNDPUNIP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFz
cz1jUkxEaXN0cmlidXRpb25Qb2ludDBiBgNVHSAEWzBZMFcGCWCFdAFZAQIBAzBK
MEgGCCsGAQUFBwIBFjxodHRwOi8vcmVwb3NpdG9yeS5zd2lzc3NpZ24uY29tL1N3
aXNzU2lnbi1Hb2xkLUNQLUNQUy1SMy5wZGYwdAYIKwYBBQUHAQEEaDBmMGQGCCsG
AQUFBzAChlhodHRwOi8vc3dpc3NzaWduLm5ldC9jZ2ktYmluL2F1dGhvcml0eS9k
b3dubG9hZC81QjI1N0I5NkE0NjU1MTdFQjgzOUYzQzA3ODY2NUVFODNBRTdGMEVF
MA0GCSqGSIb3DQEBBQUAA4ICAQB7URyOT3QnB8qwB111LGdfhczBFWX0JA5bC/gj
7mWK5DncwQ1DlLyBQFcfO7NGDCr6QGz2TSjGCCrcNps1LYAQFMOOoR8hhCllOKW/
mBnVtG2oPKc6/Nu6GLUiHffYG1zFtJHi/gKi+xRhsJQ7bMJFr8O16l8mZ4CgIGgF
9PJUlMfvP6sceD8GL5svyB2XhHe7MelXMnWuHi6cQIjDjdVDDEdtNWwP1lE3YbyU
48uOETmOjHs6te1BC/unuHkxTdMsgL9/9NN+SfkY3wJ+c/GdpJMDKy6m3/yI5/eo
ePtA3xpYtSiHPLn8VVZC0Yvkdcde7Zh5ZFnk5FsnTWEfsCrLHm2wfvtQWvCIdu1g
hjaXf+Fp5/AKLj+Z4HQt7wsmqFZNOOw3dCLyXEQDNSgvttHxNiR/Xr1EeRk3gB95
YW8ea4AYATMGwxfnm9iiZGYTmia+jYNu+/oi4QubkpTkqDvqEPCOzGj7uGacAfLh
Bnt+Cd0fAvND15DTbW+o1QC7Aj27z8SITJ7us6MUGGS4dIVsPAQW5T94vw2dNBfC
SGqaxrvcZqY57e3MK5UowDWrVx8AJ6+qmuKevzDmdus/3mRfyj/2IB0uzTVII9tN
17wb5oQGq/fMJN+zl5TkrEFwzGtD6awO6Ss1SowoerfQu9FHF628MxA5AhPuP3Yt
Ks8LPw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGuDCCBKCgAwIBAgIPGReV3CJ0GxId21RMXMvcMA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxHzAdBgNVBAMTFlN3
aXNzU2lnbiBHb2xkIENBIC0gRzIwHhcNMTQwOTE5MTQxMDI1WhcNMjkwOTE1MTQx
MDI1WjBUMQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMS4wLAYD
VQQDEyVTd2lzc1NpZ24gUGVyc29uYWwgR29sZCBDQSAyMDE0IC0gRzIyMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnrf0T2JFsx4NPb+TUBInPgv9nUyF
9dMJh7sQL66HybrB2devqNc1+Gq+fFT4tfBa9hbI+xqRRqCO0LoQOJ3v3XMlOzQ3
zTL+b3wgDvs/d8tZ7LWGOSYF480/rL1aaBIQFlrE62GDQvcmkH/C8QxsSS+T+ga2
FQhC/Br/btveNcP6cz87WyshF8IU/7sOKYqh3o5mbxI641R1u3+zaiGq8A9620pS
oW3b9P1Mf5t4z51ifqb+/QsYtDt60dw+mVES6sk8cl9VRLejcuiXFyVJaj7YyITi
or33buzheHvzZdxaQSgeq0mIrvmXqtplZoqXQ12irR7xhuf/w9UtFBbqCwIDAQAB
o4IClDCCApAwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
VR0OBBYEFNoy+Un4UcyYcWYM2c6225I/CUvvMB8GA1UdIwQYMBaAFFsle5akZVF+
uDnzwHhmXug65/DuMIH/BgNVHR8EgfcwgfQwR6BFoEOGQWh0dHA6Ly9jcmwuc3dp
c3NzaWduLm5ldC81QjI1N0I5NkE0NjU1MTdFQjgzOUYzQzA3ODY2NUVFODNBRTdG
MEVFMIGooIGloIGihoGfbGRhcDovL2RpcmVjdG9yeS5zd2lzc3NpZ24ubmV0L0NO
PTVCMjU3Qjk2QTQ2NTUxN0VCODM5RjNDMDc4NjY1RUU4M0FFN0YwRUUlMkNPPVN3
aXNzU2lnbiUyQ0M9Q0g/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29i
amVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MF8GA1UdIARYMFYwVAYJYIV0
AVkBAgEGMEcwRQYIKwYBBQUHAgEWOWh0dHA6Ly9yZXBvc2l0b3J5LnN3aXNzc2ln
bi5jb20vU3dpc3NTaWduLUdvbGQtQ1AtQ1BTLnBkZjCBxgYIKwYBBQUHAQEEgbkw
gbYwZAYIKwYBBQUHMAKGWGh0dHA6Ly9zd2lzc3NpZ24ubmV0L2NnaS1iaW4vYXV0
aG9yaXR5L2Rvd25sb2FkLzVCMjU3Qjk2QTQ2NTUxN0VCODM5RjNDMDc4NjY1RUU4
M0FFN0YwRUUwTgYIKwYBBQUHMAGGQmh0dHA6Ly9vY3NwLnN3aXNzc2lnbi5uZXQv
NUIyNTdCOTZBNDY1NTE3RUI4MzlGM0MwNzg2NjVFRTgzQUU3RjBFRTANBgkqhkiG
9w0BAQsFAAOCAgEArevbqCOPH6va0x4oEb4UviyXJzIokl5MjRADlGMDFXaKm52m
U+IZlJ9PjcqBiEXhjjD1oR8uV5aVRWXH+auI6JgQZz5L+u2a309bDu3bcineP45v
Z+nAuoDvulmx2nqjloCOturaks727w/nHCoz723eYH46fg//q/a5QnOoBe+WIiZW
T71TcycX4hiVcPwVqB53tL9IM2qe2balnCpZKorZWVHQXYWSO5MIBaw/iMOwCCpf
lDRU75TruHPjfE4Bu4U9Nm3NBt3zcc5ykcQ8ZbJzkWLnSi2LY8r71Ulc3jxqyWOZ
QbgS14x/BzVQj4Rk9+X8KovGpooAFVIBR/bdU/z2IdZlENgoPNpJokuEH5OS6UZS
yNmhhXjI2QGXn91G+QV4++kreVz6heVOhDPgOoOfRXLYG9O/9wqPMthmUQgcTrym
p57bPpM0zIYpHxcKfxhoYprQdO3LuU1F2xkZE2vFLWVB9ugHzXd1ADIKrrGgJXPf
MluXT9wK8BzTcI5cOqhESt4Awq5q9fmiW3OUAROL0Ca0Z/sRQcvvJ/ewlZvLdsym
cfjV6JtN7/IBgIJ4D/Js4DRWCwAv1jhBiEGsRAlhiJmep//U1HEaT9oredt9PYS1
iKbkcMuDEtPuYXrQ+8OQmMEwMbOFboZMMTOVNOenLH+EiG6BUnowTwqqjtA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGtzCCBJ+gAwIBAgIQAPodqurJs6X6V5gLmXTaMTANBgkqhkiG9w0BAQsFADBF
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMR8wHQYDVQQDExZT
d2lzc1NpZ24gR29sZCBDQSAtIEcyMB4XDTE0MDkxOTE0MDkxMloXDTI5MDkxNTE0
MDkxMlowUjELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEsMCoG
A1UEAxMjU3dpc3NTaWduIFNlcnZlciBHb2xkIENBIDIwMTQgLSBHMjIwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQzxIi30mNQL6Fa6afsl9Fs7it1XQS
fLb+T3omoxS2IJiUNVCoyMeBEVSFB2a0tEUnyOjfcSn++++pWoAOkU5wWp7bbNo4
yq/T5LBg1HcuPm+wH94V4IwAFFatfZIIrmaTfVRzrZ26CrEM2vISb/1u2SVzAnmP
WoY3JVGbDOXw5HEpI6W/zLnd6cetY/ZPwp/9UICzCQxD5PmPiSP18dhTnm8LP4G/
go5VK5JQu52NvH9iStYs9VVXvHiq7+1RdkQa72CmB9wx6MmXqv3MAde/tt03L9o5
uB6VPx2uJQ6G0S+gpyqwKbeUBhJxBZNRRftXyXnZxg48ZBYb26tiPfTVAgMBAAGj
ggKUMIICkDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV
HQ4EFgQU5/Hn/S5TrRHlgRpXpHOPEn2YyK4wHwYDVR0jBBgwFoAUWyV7lqRlUX64
OfPAeGZe6Drn8O4wgf8GA1UdHwSB9zCB9DBHoEWgQ4ZBaHR0cDovL2NybC5zd2lz
c3NpZ24ubmV0LzVCMjU3Qjk2QTQ2NTUxN0VCODM5RjNDMDc4NjY1RUU4M0FFN0Yw
RUUwgaiggaWggaKGgZ9sZGFwOi8vZGlyZWN0b3J5LnN3aXNzc2lnbi5uZXQvQ049
NUIyNTdCOTZBNDY1NTE3RUI4MzlGM0MwNzg2NjVFRTgzQUU3RjBFRSUyQ089U3dp
c3NTaWduJTJDQz1DSD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2Jq
ZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwXwYDVR0gBFgwVjBUBglghXQB
WQECAQYwRzBFBggrBgEFBQcCARY5aHR0cDovL3JlcG9zaXRvcnkuc3dpc3NzaWdu
LmNvbS9Td2lzc1NpZ24tR29sZC1DUC1DUFMucGRmMIHGBggrBgEFBQcBAQSBuTCB
tjBkBggrBgEFBQcwAoZYaHR0cDovL3N3aXNzc2lnbi5uZXQvY2dpLWJpbi9hdXRo
b3JpdHkvZG93bmxvYWQvNUIyNTdCOTZBNDY1NTE3RUI4MzlGM0MwNzg2NjVFRTgz
QUU3RjBFRTBOBggrBgEFBQcwAYZCaHR0cDovL29jc3Auc3dpc3NzaWduLm5ldC81
QjI1N0I5NkE0NjU1MTdFQjgzOUYzQzA3ODY2NUVFODNBRTdGMEVFMA0GCSqGSIb3
DQEBCwUAA4ICAQCOLN7o1oxUHESHOxMtyaF0+Mehvb5xp+4BL9kuUI7GQdY9HiGZ
YLSVhQ+gzKK0/TpxZksZ3klVUpyjqmBZruaTWhd5p0K4hTECK6g3zNG7zDkAR9ZZ
S+O991u0FlqASfWNWKc1n6J4Lu/wyGv72NuqNA/SbGscP4+fOX8yelJ2KFONxQNI
jftNyHX8lmlUj2YAh49yiWkPY1tsFfKKzqNJlTEIEFkJkOIM7wVRIPgRu23jhlpa
jCIayCarJ41gn/UHXVgo4oDmrIA1aE9F2prtHWn+Yd8vtQkixPwJroq1Y0na76WS
j7xnQxSEr7/aXUjPn498Pw3iD+76Vub8nislsEFYjn21pXOWGjr5PciCqdivV5kf
HWo+p6isSu5hW6lkEzKa9bEKZsiUF4NzZeobDegyer8TYXkEDP91oD1iDum0i87k
sljy3pKPKr4Aa5HEDof4Kn2ZWckemrbJwVVxHddoQ3LU004zZUjSAfmmhwcPymCk
CnSXAtLkS8Fz40wHvB1HgpBLLu/ds9gmupv3o4ZPlgbYfQelIKes4Vtg8x/23scU
bv4vuScmpyzbjYrqhAmGafUoCbamKTv/1KfIcTHJrWV8eakrrqI8aSkmcY5jBSyg
IZ+muisznpeXBNZI4fJM/jFJF9W4jqLysCU9w9aDacEsRSLeSVUkc1TN7g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIH5jCCBc6gAwIBAgIQAM6m80pTVeoL0yP3WDrKGDANBgkqhkiG9w0BAQsFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xOTExMTIwOTMxMzVaFw0zNDEx
MTIwOTMxMzVaMHgxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcx
MjAwBgNVBAMTKVN3aXNzU2lnbiBBZHZhbmNlZCBQbGF0aW51bSBDQSAyMDE5IC0g
RzIyMR4wHAYDVQRhExVOVFJDSC1DSEUtMTA5LjM1Ny4wMTIwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDKF9pp9NAgsc68LWfMMofsa7jXyUXg1MsfQYUt
ogSPPM1nZi1bE3f3y7NYzpndmwAt4pcCcqsu2pzGMZHm9SQWJBoxG9bOfl3r8y5V
kNu4zXUZOm+6vewk5YXdLMd/GFwouIe/y7IlYNoseRIP+FL036PEVQxN8DLqZIiK
LmIsOFoUI2w5MMcrsSaDOsoMeqTVjRxLIA3mhc/mDK4eT/qJVSAjpk4OOVDqv9fd
T0kriRQg92S1oNvjgUrVu1W7iS4l2ymNLmfm/y0PuyIJr2f7SnTOgBsZMg80vSg5
f1hHTv4ougOebZ+9mhzIes6iQ7H2Kj5ffYDjPjR95Fg6GmqJXKTfcIEilROms4Xi
kzxU+EEnyF8KLVhkEm+qbYttTIlbClbQp0FI5zRc8M63qTEHTOPCdqul+RJhqvMt
ZLVNY0TyJPBkRJm7d4jYDezUKpL0Qiqt7r6E/OokANPA8hDinFijIIhY/9PEBVpI
busu5m6RAo3xrM26VkprKwrPqaX0AHvqCJsa/XwaejNLrfKDe6jtICCB/Uuq3O6A
oKer3593143xNpqobbwCnSS/OYJPJbgVdjeL9Sdck33hoTFUpmNz2IAm6YbJsJ5K
Cj+ttZpIGqPlcutwA4XqW+zjlOSHmUcdrKnCtCwC/1c7mTsffxEIw57tYFTEU7VO
L0nZYwIDAQABo4ICmTCCApUwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFDKlfjHYQtu6LLL+5mkJnbfakNIQMB8GA1UdIwQYMBaA
FFCvzAeHFUdvOMW0ZdHelarp35zMMIH/BgNVHR8EgfcwgfQwR6BFoEOGQWh0dHA6
Ly9jcmwuc3dpc3NzaWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURF
OTVBQUU5REY5Q0NDMIGooIGloIGihoGfbGRhcDovL2RpcmVjdG9yeS5zd2lzc3Np
Z24ubmV0L0NOPTUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlD
Q0MlMkNPPVN3aXNzU2lnbiUyQ0M9Q0g/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MGQGA1UdIARd
MFswWQYKYIV0AVkBAQEBCjBLMEkGCCsGAQUFBwIBFj1odHRwOi8vcmVwb3NpdG9y
eS5zd2lzc3NpZ24uY29tL1N3aXNzU2lnbi1QbGF0aW51bS1DUC1DUFMucGRmMIHG
BggrBgEFBQcBAQSBuTCBtjBkBggrBgEFBQcwAoZYaHR0cDovL3N3aXNzc2lnbi5u
ZXQvY2dpLWJpbi9hdXRob3JpdHkvZG93bmxvYWQvNTBBRkNDMDc4NzE1NDc2RjM4
QzVCNDY1RDFERTk1QUFFOURGOUNDQzBOBggrBgEFBQcwAYZCaHR0cDovL29jc3Au
c3dpc3NzaWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5
REY5Q0NDMA0GCSqGSIb3DQEBCwUAA4ICAQBAoZC6vwyjeHq6F/b+r8csNmOXuzQL
pYz2DU+/uHQ1HuBxateeGWZoTpznruX91ksJqgjjmrx9tc6Bbqp3tV3j2cyjOO27
Uhq0RaNku82AdS35pplzliSWtl/gwDCqVQ8FBWD9h5qDnDZHrU4jyoV91ZRgJ249
sTQ4b3opF6bOBa40MNWSnS26oWFth5QfrepRxDF+nXOrqxDdmXEO8Uese++Bg6WF
gNzgrCXYPZ008Rv9rTYdbTcPn4pL/2HzOiPJay4Hr4SJr0krC9MrIVARGDGSuxQm
zEc1SwZ6MzFeHR6qOWTE7sKM/TmrblgNeUuZdRxIlynO4KSFLOkqMM17Jpb1Tf/q
glhRDc/8TWYJPhRJuepu4n6HCV9ovtB4FRgiJZ6H1iR/rNZEQstQuSur7o5VmSXK
v4IDmRXTJSm1XndxyIkW3kIng7T431e62ws6X9ijeo3gVvUz79TMaA1qomwyy71a
w0j6VHIh/u3v2O4BGkdLMH0UqQbXtCdQ23RkQrRTc866CbcHM58yBgHzktJZ1sla
evwZrM3J4pDTzn9hE15x6E8ETNzmYVk7jceoo0mc81gJBSLxM7lFukQM9yQ5eD5P
9OqSYod+HJM1nwUBIGewoYN8nsjcgltBP8WojvGSl9HCOM1+LzbBGhcbQAa1DCHh
OaJ221j2KtEASA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG8jCCBNqgAwIBAgIPZFbPgPnHoDNUN/U3JQcFMA0GCSqGSIb3DQEBCwUAMEkx
CzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxIzAhBgNVBAMTGlN3
aXNzU2lnbiBQbGF0aW51bSBDQSAtIEcyMB4XDTE3MTIxODA2MjUzNloXDTMyMTIx
ODA2MjUzNloweTELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEz
MDEGA1UEAxMqU3dpc3NTaWduIENIIFBlcnNvbiBQbGF0aW51bSBDQSAyMDE3IC0g
RzIyMR4wHAYDVQRhExVOVFJDSC1DSEUtMTA5LjM1Ny4wMTIwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDP4eh7M8UJfdm4LJGKXpmg7MiwOqa1+XVYi5um
65UoGtikYXFDa9kIihcOOg3/nOxDJ8j02lf6vx2c/FfCVG0PT1hQfLiP3lRlVnhY
ovx7k6o47iqDOUrW9173EmsduhoO1NmxlmBFxg6XdsKJwHK+atT4Un5DxSNuqTen
Z49H5o1UFTT5YMz+F9DJR0EbuQ+Mfo3FBNdg2G3RQD75I65E6THdrG8rdGiFN817
x1EhN269auMRUjnYlYC2IPFsOUFpxJmaomxPEo8vxFL3bWRh9NUk0eIkPL0RNTx+
oEhuLy00LhAFSvlVjKXSKRCcq/iwPFjPY+PEyz7rVU4MqyijAgMBAAGjggKlMIIC
oTAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU
HsgEbftyYlFgonMkb77yX000kvwwHwYDVR0jBBgwFoAUUK/MB4cVR284xbRl0d6V
qunfnMwwgf8GA1UdHwSB9zCB9DBHoEWgQ4ZBaHR0cDovL2NybC5zd2lzc3NpZ24u
bmV0LzUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlDQ0Mwgaig
gaWggaKGgZ9sZGFwOi8vZGlyZWN0b3J5LnN3aXNzc2lnbi5uZXQvQ049NTBBRkND
MDc4NzE1NDc2RjM4QzVCNDY1RDFERTk1QUFFOURGOUNDQyUyQ089U3dpc3NTaWdu
JTJDQz1DSD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xh
c3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwZAYDVR0gBF0wWzBZBgpghXQBWQEBAQEH
MEswSQYIKwYBBQUHAgEWPWh0dHA6Ly9yZXBvc2l0b3J5LnN3aXNzc2lnbi5jb20v
U3dpc3NTaWduLVBsYXRpbnVtLUNQLUNQUy5wZGYwgdIGCCsGAQUFBwEBBIHFMIHC
MGQGCCsGAQUFBzAChlhodHRwOi8vc3dpc3NzaWduLm5ldC9jZ2ktYmluL2F1dGhv
cml0eS9kb3dubG9hZC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5
REY5Q0NDMFoGCCsGAQUFBzABhk5odHRwOi8vcGxhdGludW0tZzIub2NzcC5zd2lz
c3NpZ24ubmV0LzUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlD
Q0MwDQYJKoZIhvcNAQELBQADggIBAHPgWaDtoRXD/UeOCPeqbJNmHz2Y1IkuulXt
UP1B9g/+9s9rw/E3DGa6Z7iLqzK0EEhfQKBZpJirEu6EDR023IQhzRh/lI7BcjMP
OfEUM6E00rIS8UZrRW9SnymNrbYTWE8FS8jsfFd/pppY22NolKn3UlUH1RYupDOG
Wj/TMxtMmMG7HMQeLj74sK8pEnQSt+VLHWUYabW7VnO/DcZrrw9FPMHUyJElxWgP
wngl48Dm/tkTsXwOpnTiZ5XmEEwNC24yLG2y8+QMxCt3Nacrqv5s5PTbsr23BkTl
Owy5BwN99ZfmeCcUI8egA4gH3EzAV1a5ONwaIvvODXr1RIwTWiV8WLLSWLywLP/2
m+GUZYLpjMUmLq/qtBGT+KBHGbSjd0fwOysKIN9d2eA0xZwziXBCIhDT+1B4S2U0
dwaZBje6OMo+toMeBPsDtBTuoKFdfq9O9KFTHsnMaHh4YeR3SYzhPoemRpaB4hvX
+evVKXQKvtOnATPAzFCQwv10qt3xlREhq8NJOgV0YvELz1LPD1n/VUQU1UW/IjC9
/igroSCAPaZh4krhypMWTifbRl5pymP9njZZOlaTwMnZya9e5+tzuyZ4nBP3dYJf
peTjabxa3mNOC1+pXX2LZLdlRyA5s0um58mOUKzTQKJnX1dv050EjBADTBh4P2FR
Tlj5QwBS
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGbzCCBFegAwIBAgIQAKZAQ5cBE2dWe8qWBnpU7TANBgkqhkiG9w0BAQUFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xMDA3MDUxMjEzMzVaFw0yNTA3
MDExMjEzMzVaMFcxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcx
MTAvBgNVBAMTKFN3aXNzU2lnbiBQZXJzb25hbCBQbGF0aW51bSBDQSAyMDEwIC0g
RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPWbTxjDlowAYuwPYj
IVxIyxypG3ub1VcX/9H4235YhTFEURY7r/qjL6vwrm1LvZjdRhGn7VKXRuaSQDCx
trFfNb1/gh2pgxcWzNyWK9l6SUdLwlK7FjKANGu3TSNOlJ/Z/tRbM3Fe2HZ6B6FS
Bp8V2Y+G7VZ/TkMXpuxJLe4tIayBWwf4d37uTaXmvvjNLEfEZW79fa1Qg9h+fytr
PPME5MbEXpjCqkgC3oKR5MsZaMV0mfsdsr5xFFXxbXssicwOwS/fLgEe4EglvL+v
iU7sjAkSbwV9Bb0J97UJvl3Lkn1jIlmGHYzWbx9JOwVRAjlPubcXj0xPsPPhPIlE
7wYtAgMBAAGjggJDMIICPzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB
/wIBADAdBgNVHQ4EFgQUStQ7hu8QU46v5Ex3WUeC/QARdogwHwYDVR0jBBgwFoAU
UK/MB4cVR284xbRl0d6VqunfnMwwgf8GA1UdHwSB9zCB9DBHoEWgQ4ZBaHR0cDov
L2NybC5zd2lzc3NpZ24ubmV0LzUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5
NUFBRTlERjlDQ0MwgaiggaWggaKGgZ9sZGFwOi8vZGlyZWN0b3J5LnN3aXNzc2ln
bi5uZXQvQ049NTBBRkNDMDc4NzE1NDc2RjM4QzVCNDY1RDFERTk1QUFFOURGOUND
QyUyQ089U3dpc3NTaWduJTJDQz1DSD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0
P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwYQYDVR0gBFow
WDBWBgRVHSAAME4wTAYIKwYBBQUHAgEWQGh0dHA6Ly9yZXBvc2l0b3J5LnN3aXNz
c2lnbi5jb20vU3dpc3NTaWduLVBsYXRpbnVtLUNQLUNQUy1SMy5wZGYwdAYIKwYB
BQUHAQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vc3dpc3NzaWduLm5ldC9jZ2kt
YmluL2F1dGhvcml0eS9kb3dubG9hZC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVE
MURFOTVBQUU5REY5Q0NDMA0GCSqGSIb3DQEBBQUAA4ICAQBZiJ342eaawsEV3jtv
keLC59c779N81fN78DAmepdcXjwGaHn6Zo5QCCIdJZ7dqfGiRUnfVT1cvV5ISinx
kkJPHMBschmJpNCUVmXuSDVHDMblcqpt4SgkMx9wR3NbFqi2+NggudCLHP5tK7sc
sglQn0+uC6acAUlcJUGfe9q1YydcLHq5SLvKNPX2L2aaAIEdHOfmWq2AwlEKEiSq
M30aM5ZOs5pdoRV+laHv5vlBLoo2iT+X4x7AkZW+I+M6VqTTF1XAsrhmeg0sIl72
isDv27cbcQRR7BCVq1n0yvSqx0gIO29FT3U+CoUSJlDKLZbOidjkmhCGNx7SUE/r
FgykHhNiVRE9yolFopyhywKCB/5NjeG4CjCiZx57JDvPLb4maxQi3mGPeTB8x0DX
4jGH2/V0G+BYqBYyGH9JWXcFOoF5VG6zKFHjwJEHoDIGpxasjhnXZSQ9lFeZ5FlI
kiD5H0DvrvJZP5W+5Q/gBjSbC8BE7LtxBB9A62qFSMC/3jwWjl4o53x6mOgrZ5gb
z35mW0WmU3kKRYYa5XzR4kwqwO248ZuQPf8wm/7V3pSkv4b2YDoDFbgA026LHycc
X7Pw/V+aKpYNuG0MZrn8fw8wNMsTXhyObOH3EU/+lBqoUNSiy10GAabhwD4dCU6r
nxY8lNMfBYFnBfKPhDjtlL6jpA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIHYjCCBUqgAwIBAgIQAL8nS46x5IonF4Zd2FEJXTANBgkqhkiG9w0BAQsFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xMzEyMDkwODUyMzZaFw0yODEy
MDUwODUyMzZaMFwxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcx
NjA0BgNVBAMTLVN3aXNzU2lnbiBQU1MgUXVhbGlmaWVkIFBsYXRpbnVtIENBIDIw
MTMgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL2csDFQi11X
3h51PUi4V3WIYUIf6x8EJ7loCFy6IsmAEgZuRJv6KHAJJqNmpCPaVhEV6TQGO/tf
luC88Zps1p5dV/giKotjEyrnJFNKfaHwft2PtIsTg7DRVY2fjRz9JnOQPAFDniD6
289kyO9dhy7S6bPZ+RdD3P50DIsw/Xh+OKXsWuch6/ABIGbEXVj8rzN0EtoludKo
hhm0c8JTXWtKzND1IlhYrZqj7JJoBI7QfhQ0B1XvMf/7rUFzIbLFJC3zNzEPSdsw
quSdFxJxDE8xIkGhSfFFa9zxO/86x+nOcgp0Zmr7/gy0JdurVnt0QwGWvbTCBRky
lfrYh8H2lUUCAwEAAaOCAzEwggMtMEUGA1UdEgQ+MDykOjA4MQswCQYDVQQGEwJD
SDEpMCcGA1UEChMgWmVydEVTIFJlY29nbml0aW9uIEJvZHk6IEtQTUcgQUcwDgYD
VR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFObz44M9
ykfwL+Em8NUtA3FipQWIMB8GA1UdIwQYMBaAFFCvzAeHFUdvOMW0ZdHelarp35zM
MIH/BgNVHR8EgfcwgfQwR6BFoEOGQWh0dHA6Ly9jcmwuc3dpc3NzaWduLm5ldC81
MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5REY5Q0NDMIGooIGloIGi
hoGfbGRhcDovL2RpcmVjdG9yeS5zd2lzc3NpZ24ubmV0L0NOPTUwQUZDQzA3ODcx
NTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlDQ0MlMkNPPVN3aXNzU2lnbiUyQ0M9
Q0g/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
TERpc3RyaWJ1dGlvblBvaW50MIHjBgNVHSAEgdswgdgwgdUGBFUdIAAwgcwwTAYI
KwYBBQUHAgEWQGh0dHA6Ly9yZXBvc2l0b3J5LnN3aXNzc2lnbi5jb20vU3dpc3NT
aWduLVBsYXRpbnVtLUNQLUNQUy1SMy5wZGYwfAYIKwYBBQUHAgIwcBpuVGhpcyBp
cyBhIGNlcnRpZmljYXRpb24gYXV0aG9yaXR5IHRoYXQgaXNzdWVzIHF1YWxpZmll
ZCBjZXJ0aWZpY2F0ZXMgYWNjb3JkaW5nIHRvIFN3aXNzIGRpZ2l0YWwgc2lnbmF0
dXJlIGxhdy4wdAYIKwYBBQUHAQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vc3dp
c3NzaWduLm5ldC9jZ2ktYmluL2F1dGhvcml0eS9kb3dubG9hZC81MEFGQ0MwNzg3
MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5REY5Q0NDMCIGCCsGAQUFBwEDBBYwFDAI
BgYEAI5GAQEwCAYGBACORgEEMA0GCSqGSIb3DQEBCwUAA4ICAQAgPp8OtAYjFHeH
LY/djzGzefGvsqvrSVrHD12L6KCq9GYdWxl8CiFsCxAUaPRZiKqyf9ksDV38y79M
yPO7OuyCRV6xWB9XfODaeRI5z0hdQkjXcLWIc0yKSJw5PBMBxf+ZkxrVVG9DYCmw
D9+F9xFN3yCk0VOJddnuMoaIqATh3XJmVOi4jmjvwDMIUS2CSaKqI939RW5OGilu
2GNZSbXUESGBOLII9JVITsOv3lws7caEZJls5Ewjz6uRAHSPIY8IsMWAD22rFtDC
/74khJezYwk7I4/xrMZBGgEMXLYQmcnGd1N6w+590+hgyE2MQT94K7DFUwV1Xo/Q
A75NdENhsxc3wj2EnQa8L4zTEVA0KzWlz8McTe1D+wOLIdrmlY/OJ1EXG5O++Upx
Q2bKRM6FRx6p7hnvdLGEXav9NdBAdXK+RZU+RRDBAc/0M2rKs1/VBDtlfu1ku22g
nClNmhqtmXjvQF0ABEbMMZt5zeXZPNYKmJ6YJaJaXwvfa7Ya0MuQDKaANlm6nfMa
xvghEMrujsp862JYdylGossiZOuWRao8TIvxQx+1o7aFVwatApYj0atOZ0NQiGOr
gJ2fdhdXUpgJdklRrxDBYX1jDoA0kDei4fYBz84DKOsp07grYQVDi8Qd6We8X1de
18LMXnyZdKXO/H6u+Kj072WMSjE+Yg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG9jCCBN6gAwIBAgIQALjfg3D6pU52wIhjWom9rjANBgkqhkiG9w0BAQsFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xNzEyMTgwNjMxNTlaFw0zMjEy
MTgwNjMxNTlaMHwxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcx
NjA0BgNVBAMTLVN3aXNzU2lnbiBDSCBRdWFsaWZpZWQgUGxhdGludW0gQ0EgMjAx
NyAtIEcyMjEeMBwGA1UEYRMVTlRSQ0gtQ0hFLTEwOS4zNTcuMDEyMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAugv1YdAdGpjKgjiMSYTduGb+3XDhI2cm
gTcm0EGEIOhR3YiEsJIQfG3e7GqTvbkkBEaxt5IBnehz2gcIkUlo4LYfi1shUzCu
PLvy1T463uWbC8fIe23JzW4ck6wHPGOQm4sIKyLfZnmKdwoOiULUNY1dJxOr3GTZ
1rK+Ef242kbSwNw0yXolVgfqjMOkatBPJkpofXpPGB/PNTokHNzN0I/9ljzcEoPs
ArJh0+OzZZcdQt3hjxzpDg+WHcFViuZcssPuUpi/RADGis/k0ntnA8AAN3T0p8B0
10Zmkpro5fBGT0VVKNzlcByBHIfj9x4iHZRI9UXTWdxzmoEVDd66fQIDAQABo4IC
pTCCAqEwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0O
BBYEFFTwW1IK0IwJ2wfltremwnXruLkFMB8GA1UdIwQYMBaAFFCvzAeHFUdvOMW0
ZdHelarp35zMMIH/BgNVHR8EgfcwgfQwR6BFoEOGQWh0dHA6Ly9jcmwuc3dpc3Nz
aWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5REY5Q0ND
MIGooIGloIGihoGfbGRhcDovL2RpcmVjdG9yeS5zd2lzc3NpZ24ubmV0L0NOPTUw
QUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlDQ0MlMkNPPVN3aXNz
U2lnbiUyQ0M9Q0g/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MGQGA1UdIARdMFswWQYKYIV0AVkB
AQEBBzBLMEkGCCsGAQUFBwIBFj1odHRwOi8vcmVwb3NpdG9yeS5zd2lzc3NpZ24u
Y29tL1N3aXNzU2lnbi1QbGF0aW51bS1DUC1DUFMucGRmMIHSBggrBgEFBQcBAQSB
xTCBwjBkBggrBgEFBQcwAoZYaHR0cDovL3N3aXNzc2lnbi5uZXQvY2dpLWJpbi9h
dXRob3JpdHkvZG93bmxvYWQvNTBBRkNDMDc4NzE1NDc2RjM4QzVCNDY1RDFERTk1
QUFFOURGOUNDQzBaBggrBgEFBQcwAYZOaHR0cDovL3BsYXRpbnVtLWcyLm9jc3Au
c3dpc3NzaWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5
REY5Q0NDMA0GCSqGSIb3DQEBCwUAA4ICAQAZHgH/iFsDsxi3ug0fs/Ck3+s+WyA5
jauQb6HEjsSTK9sCtfl6tVhtz6KWVg14DmHeORwKPxrsVcnJGhkr8eaxhMsR2XEl
Y81gs68myFzp9iLFe0tUpC8L1EZtRjIx6tP2O8nq/2UI+2njp9PFdGEPpRGHNM2+
rEJG4tScrxFqbGpgsf78btdNNX4zTyWGCmx8cXc++j0vcIV71fRO+gAZT7lg+TMh
nUA5E1ikWUhrRIlFKYYQABOzfAbTLhu6gOTQk3G6cjAtvIqYhEd7pVmzZB9Xoo+S
ggWM/gKNbF+pW+sVgDLw1WFnTKfhgoMYa+H5RDTATgi45RneqCHuvPuFJWRBPDft
n3f3X2M8ao5oSavHQc2CHEB5Aijca8AtJojln0YKr3La0JU8NexigyXQ9eNxejWY
98OUQCxNMx5PACHOSYTMZlThqag/qT4gltjFd3Dmpy0m/I3MjTQskkdfGdgBRaDF
J/uSwCg+GKyNGePgRti91rVGNnzbp9LtncFF6/stRFxBKmxeL0TgNhBLsz0fyZGt
yodxxwFJwrsnMJxaDxrdfcBbz6NCgRq1aJjAZIwD9LHV9qEus90d1UEwr0FeyKCA
sAN2o9FlrPyKF2Cwz1Jm1cub17M0kjgHuPtPi/OrH+wlcIRlKeSle87ZtiDvtF9q
D93wxpQiQGv+eg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGbzCCBFegAwIBAgIQANXLicKTAJvtvQFL3BCWAjANBgkqhkiG9w0BAQUFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xMDAzMDgxNDA1MDRaFw0yNTAz
MDQxNDA1MDRaMFcxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcx
MTAvBgNVBAMTKFN3aXNzU2lnbiBTdWlzc2VJRCBQbGF0aW51bSBDQSAyMDEwIC0g
RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhxIQRcjI0MdxZiPdC
tU7/k4F+shRorhq74URxIV7gy9D3/BXen0MZJN/y+WNyAc08hijiIdiHzElWfscr
s8brJL4mehCyXlzwMjtQTllb+SN8ePjlb6sObKGe1CobsWM9lCg9Z2ULaUaRXY0S
16dT5TSNd/Y2lDDcuI+0XcKOWJevwF26wmS9SbQi19olpsXj7KAVr2oCb1gsZhow
1yTXsKgqwJW0N1oUqMGbcKiVl4HkYARlPB0HAWcc2n19e+f5C43CETnAxlPjqlVc
1smUKucR1uWaJYSF6L2MHnfzWFKwpqL/MtqV1VD9pK7XRZiDkoqRR9JZVVJxP6Po
+0zZAgMBAAGjggJDMIICPzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB
/wIBADAdBgNVHQ4EFgQU6USGgJLqTlB3yeeSCELXX8DCJUIwHwYDVR0jBBgwFoAU
UK/MB4cVR284xbRl0d6VqunfnMwwgf8GA1UdHwSB9zCB9DBHoEWgQ4ZBaHR0cDov
L2NybC5zd2lzc3NpZ24ubmV0LzUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5
NUFBRTlERjlDQ0MwgaiggaWggaKGgZ9sZGFwOi8vZGlyZWN0b3J5LnN3aXNzc2ln
bi5uZXQvQ049NTBBRkNDMDc4NzE1NDc2RjM4QzVCNDY1RDFERTk1QUFFOURGOUND
QyUyQ089U3dpc3NTaWduJTJDQz1DSD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0
P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwYQYDVR0gBFow
WDBWBgRVHSAAME4wTAYIKwYBBQUHAgEWQGh0dHA6Ly9yZXBvc2l0b3J5LnN3aXNz
c2lnbi5jb20vU3dpc3NTaWduLVBsYXRpbnVtLUNQLUNQUy1SMy5wZGYwdAYIKwYB
BQUHAQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vc3dpc3NzaWduLm5ldC9jZ2kt
YmluL2F1dGhvcml0eS9kb3dubG9hZC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVE
MURFOTVBQUU5REY5Q0NDMA0GCSqGSIb3DQEBBQUAA4ICAQA6hj4f0Cef1KmpWwcF
7five23ZyhWfnfzoXRSIfUiFpY0xVmirT+wqNe5an6RmuQ0CpbCG+TiqCGWXG2eA
jsNIbj7X/1Iael7wNO+eBEd6wDNWRsd8Kg2qUoYGeMKnqL5x2bM5veimPQwJ3mRC
Q+SzDdhOQFckOI1pTjdhFFdvW4QCBBuLMqQGDFkamMNrgVKzmvL5iratd5pSU9aY
JH3BlLmRnVqfJ/DJFKYVAr9s8yKQLD3JJ7bwO3P2cw3BmYc0a+EZhQX4XRAcxv6x
1sbHpMPjrl+p1h7kzv9ikSVG9LqMo49JypRmirTHGsFqRzhc9CA04KsJG7Q8qBE5
Z5Qa/fNnDy5jlfLkMmh7sXtqfEQmBPD0DjVLRYOHvkjCOv2X3VL0jN6IZHeDpLqG
t6T3w9aN0eYB8ij0UcYJJdskV9r3nyHzZAqfJ1TLv16dfBFw9u+XDUWhOQFaBzS5
x4jHeNUyVTs3IT7Q8KIwhYz9gFufQHQqZNhvaF117xgManYz6ptbbBC/WCML2+2b
QSezVt6Y3caB5ZDFBcwBhcMlZv50XLWw4jC+HOnfV6LTrHgLcS6JBcg3ORB2A4v/
tvl7mvbczjFZ0hK/0gQfA9zgi5cnY0GsHzOT1GZlFxA6N4d3AMzuf6LcWU+Mvb9K
1Xbyoi4+LDNiNCHNA4FAz7vF3g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGwDCCBKigAwIBAgIQAOKjZ925iBlAqEheVUGp/TANBgkqhkiG9w0BAQsFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xNDA5MTUxNjIzMzZaFw0yOTA5
MTExNjIzMzZaMFgxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcx
MjAwBgNVBAMTKVN3aXNzU2lnbiBTdWlzc2VJRCBQbGF0aW51bSBDQSAyMDE0IC0g
RzIyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApgky7tyv+w2JirbD
l30lH5v4JrHDKwU76slAffIE7gy5FiX6EB08/FSAiWkULdkoacAAj8+9ZXOhUJAv
id+EVKqS5ccNAlZFTF8r2964fLgiia1MCauqQkyV5pzRAP8s5UzNcfeFw0WfSP6U
RirIHEHFqM6G7Up2Nv67WjzmRfSSN/x8womdSsXvSaXweYBt/PX4/Sl893f9UW9j
SPz0uUd7m5aW8/z/+vuJAOdSXVBWLi4hN2T9Dvgbuy0n5O0xc6wVnNvZB2fxbEaF
LBtJIWu6OcpLpNWFsfyTNiZ9SGklftD5pLWCgyeERuzurdnspdf09GtlSYh0VyZe
nOMDqQIDAQABo4ICkzCCAo8wDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFPCQTIvh8ALeAAFrmOfu3FGN20CuMB8GA1UdIwQYMBaA
FFCvzAeHFUdvOMW0ZdHelarp35zMMIH/BgNVHR8EgfcwgfQwR6BFoEOGQWh0dHA6
Ly9jcmwuc3dpc3NzaWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURF
OTVBQUU5REY5Q0NDMIGooIGloIGihoGfbGRhcDovL2RpcmVjdG9yeS5zd2lzc3Np
Z24ubmV0L0NOPTUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlD
Q0MlMkNPPVN3aXNzU2lnbiUyQ0M9Q0g/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MF4GA1UdIARX
MFUwUwYEVR0gADBLMEkGCCsGAQUFBwIBFj1odHRwOi8vcmVwb3NpdG9yeS5zd2lz
c3NpZ24uY29tL1N3aXNzU2lnbi1QbGF0aW51bS1DUC1DUFMucGRmMIHGBggrBgEF
BQcBAQSBuTCBtjBkBggrBgEFBQcwAoZYaHR0cDovL3N3aXNzc2lnbi5uZXQvY2dp
LWJpbi9hdXRob3JpdHkvZG93bmxvYWQvNTBBRkNDMDc4NzE1NDc2RjM4QzVCNDY1
RDFERTk1QUFFOURGOUNDQzBOBggrBgEFBQcwAYZCaHR0cDovL29jc3Auc3dpc3Nz
aWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5REY5Q0ND
MA0GCSqGSIb3DQEBCwUAA4ICAQAwt+R/QMYqzRIatBxAcIQQpCkL18rYBfbFpPWA
X62JohEKCrhAVrrP3BFVG0qxtNSe2zgBBh5k48LQ1/FAhsZrw0+HTB9dvtyoTlJ7
IfO0EpiDy8g7i1sjCRNXVJM+sg4t5auyQ0UxdADHBJ4BXI/ie5JmwRicIyb18/ET
7+mr8jPbhvnqcumZndzhrxXiYznw9ZaXldB+BTRAaWnn2hURTVDJZhRRjazax8gX
U5FDbYPZizZbZVFY9zPr5FSaMEDo4T1NrXn/Y5J+Yj3J09qs4zdGvVJ8GiYFwBnD
CbrqzmQ+rZ+Aw6HjsmljVW/d0yMTwbLhr1QAfZQEYGzKPSU4WAbxMi4YFL6DbiWr
BuuJ38YjD+gnUcjb4bx6N6gOVxvm7ECiWsUdfS9+Ojtg1U5ijBOz8jgS2OhtR6Ax
FEDk5x3yw1IwwsMpY10Fng+7ugKiTMRTSkgxSWk143qpBGmSdulwqZTUA/YnENo4
1j/CX8W6TakZS0UoFq/dKmRqCYD+egF1AKy41TCotBOc2NV/Xr4W+uNEvYCD8yDV
qLghY1G4FHphXVrSEdmEeBqg6jAiRjOHgioCpZIrBSdwNH8qFUUvHtlMH4sJctnG
WZrqNoa5nl1wimrx4gjDRiKce2osH57v1BHHou2Cod4Bhqe7D6rqQcdjAnLen3O+
6NuVmg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIHuDCCBaCgAwIBAgIPWyQANk6dlfPocBGKvX0JMA0GCSqGSIb3DQEBCwUAMEkx
CzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxIzAhBgNVBAMTGlN3
aXNzU2lnbiBQbGF0aW51bSBDQSAtIEcyMB4XDTE2MDkxMzA4NTE0MloXDTMxMDkx
MDA4NTE0MlowVzELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEx
MC8GA1UEAxMoU3dpc3NTaWduIFF1YWxpZmllZCBQbGF0aW51bSBDQSBHMjIgMTYt
MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKSt5TJWWDUKMIDdWaDS
oATM+McP6v6FJ7UdtgZjdRCXRnQ8X7WxA66WIeHCn4Wiysf/Nbx7EYVwVKHchmlR
xDqjfWkDtMWNb+pGV+FEgVZMTHejaMmJlzlLbvE1F7eIcTDhvSwaJAnfIfp95cLp
IEZ6AYt6EKuvt9PaT5W+8vKZHNwHMA5kJ+N9O4QZgLqXho+pWtQx1n+D+ka2lDop
eOpOxw/lCO+K3egVkeQ8xzAC9gmcCH7YHfd02nrYNqY6kp/k641rkFGnhAx7jz+y
1M14Drs8YP7GTgTG7r3D+5oZnSX/qOyK/aQ4wBaenIfgC1bjvSV8NStFpYM76SiP
xRECAwEAAaOCA40wggOJMEUGA1UdEgQ+MDykOjA4MQswCQYDVQQGEwJDSDEpMCcG
A1UEChMgWmVydEVTIFJlY29nbml0aW9uIEJvZHk6IEtQTUcgQUcwDgYDVR0PAQH/
BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFF0z8lExm+OK0Fjr
t6nSi0sUAV8EMB8GA1UdIwQYMBaAFFCvzAeHFUdvOMW0ZdHelarp35zMMIH/BgNV
HR8EgfcwgfQwR6BFoEOGQWh0dHA6Ly9jcmwuc3dpc3NzaWduLm5ldC81MEFGQ0Mw
Nzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5REY5Q0NDMIGooIGloIGihoGfbGRh
cDovL2RpcmVjdG9yeS5zd2lzc3NpZ24ubmV0L0NOPTUwQUZDQzA3ODcxNTQ3NkYz
OEM1QjQ2NUQxREU5NUFBRTlERjlDQ0MlMkNPPVN3aXNzU2lnbiUyQ0M9Q0g/Y2Vy
dGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3Ry
aWJ1dGlvblBvaW50MIHgBgNVHSAEgdgwgdUwgdIGBFUdIAAwgckwSQYIKwYBBQUH
AgEWPWh0dHA6Ly9yZXBvc2l0b3J5LnN3aXNzc2lnbi5jb20vU3dpc3NTaWduLVBs
YXRpbnVtLUNQLUNQUy5wZGYwfAYIKwYBBQUHAgIwcBpuVGhpcyBpcyBhIGNlcnRp
ZmljYXRpb24gYXV0aG9yaXR5IHRoYXQgaXNzdWVzIHF1YWxpZmllZCBjZXJ0aWZp
Y2F0ZXMgYWNjb3JkaW5nIHRvIFN3aXNzIGRpZ2l0YWwgc2lnbmF0dXJlIGxhdy4w
gdIGCCsGAQUFBwEBBIHFMIHCMGQGCCsGAQUFBzAChlhodHRwOi8vc3dpc3NzaWdu
Lm5ldC9jZ2ktYmluL2F1dGhvcml0eS9kb3dubG9hZC81MEFGQ0MwNzg3MTU0NzZG
MzhDNUI0NjVEMURFOTVBQUU5REY5Q0NDMFoGCCsGAQUFBzABhk5odHRwOi8vcGxh
dGludW0tZzIub2NzcC5zd2lzc3NpZ24ubmV0LzUwQUZDQzA3ODcxNTQ3NkYzOEM1
QjQ2NUQxREU5NUFBRTlERjlDQ0MwIgYIKwYBBQUHAQMEFjAUMAgGBgQAjkYBATAI
BgYEAI5GAQQwDQYJKoZIhvcNAQELBQADggIBAJ3CXiaHty0ED3Qod7ELia8RSkGK
+Z59rcZLI0eNLjJ1AJriZkQJDByq0BaIiwgXLSBWEQoBEZppP3E99suJqLnSU4Bl
9Zzhb66NwudQImPxPZYEfmHT4WGqU8kMENH0X5KaHZ1RlmxRZto4TnVl5O2BaOAJ
Jpy2zOZTkEa5i01gWJ1ypfhSidcXUNeIyVNyqAbYN9dXoEtBGJdGp1E4qaGk1lsA
CVTSBsnI1qLKyZhElMMcBSeJ7GHR91Yz2Exi2QF9Z/cAmkuOSVuXtybSmMqFBTj4
w+LbeZndaQYL3hXM/57Th89KLhJXUM3hiBoDltPrv612TJ6iyzs/vB4eP/5m6d9y
2+3RrrpK0NNmpYXARWSjBKmMn8JEH5ZInhzfwZdhYE/4rXjhzql2eRTCBz3J4QHP
2V9D3MAZTpPgaTC52P0VIgqfyzo4kw2Fn8cq9b4dWGrBxsIj2HEGUkeFNrnjeIL2
9bMEyXbng0SQerMn3BWWLisdMK4b2ElvU+uHEELld2ks4dk1mlBv5AbQRs0neu65
ixo01Wg/3/6zRfJ0ald12oDuxtv/FLLVnFiFPun64iK6bb5wp5W40tf7lRfVEzRB
t6++DTATVizjPtXR2Y3DnsAX6NvL92de+xTdkVHKI0AH2+avHsnK2YObwXNn8aKZ
fw2GiyZrmnswI4+i
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG/DCCBOSgAwIBAgIQAPWIniGIYRfiVdZFgQVW+DANBgkqhkiG9w0BAQsFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xNzEyMTgwNjI5NTVaFw0zMjEy
MTgwNjI5NTVaMIGBMQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFH
MTswOQYDVQQDEzJTd2lzc1NpZ24gQ0ggUXVhbGlmaWVkIFBsYXRpbnVtIENBIDIw
MTcgLSBHMjIgMTctMTEeMBwGA1UEYRMVTlRSQ0gtQ0hFLTEwOS4zNTcuMDEyMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJsL6WuEG97ZSgGAL/+zO5PL
/hqpD5gDpuI7lGypmuI52v2/H9KDJ2DjHQjw5sk6vwdJ/mqFyHzuMTvywwCd2FQR
C9Rhd7G3EbNAkj2AU2sIFhiLI6CaVmOXEwS5igw2Txb15xVXqjyHwOHaUdX007zy
8i7rlSqFdrcDSFxZfVhHcyhE54vbDqgYzcd2D8kCQsjn0nuUXTYXUHGgvFoiLrX7
ITTQPp7bWbsdGNOv7S6tgscdFony4u0JVHH525FbUUuf90+GQ78Imwt1KTa2Tlpv
bHYxRUEmxWuqJw27zY8Lixdz3b/6/GvVf5n7k+av9AlHXQhifHUSO0SGZHZ2ZwID
AQABo4ICpTCCAqEwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
HQYDVR0OBBYEFP3+/Y6c9H4tKdEoYW2g3KdQduP+MB8GA1UdIwQYMBaAFFCvzAeH
FUdvOMW0ZdHelarp35zMMIH/BgNVHR8EgfcwgfQwR6BFoEOGQWh0dHA6Ly9jcmwu
c3dpc3NzaWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5
REY5Q0NDMIGooIGloIGihoGfbGRhcDovL2RpcmVjdG9yeS5zd2lzc3NpZ24ubmV0
L0NOPTUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlDQ0MlMkNP
PVN3aXNzU2lnbiUyQ0M9Q0g/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNl
P29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MGQGA1UdIARdMFswWQYK
YIV0AVkBAQEBBzBLMEkGCCsGAQUFBwIBFj1odHRwOi8vcmVwb3NpdG9yeS5zd2lz
c3NpZ24uY29tL1N3aXNzU2lnbi1QbGF0aW51bS1DUC1DUFMucGRmMIHSBggrBgEF
BQcBAQSBxTCBwjBkBggrBgEFBQcwAoZYaHR0cDovL3N3aXNzc2lnbi5uZXQvY2dp
LWJpbi9hdXRob3JpdHkvZG93bmxvYWQvNTBBRkNDMDc4NzE1NDc2RjM4QzVCNDY1
RDFERTk1QUFFOURGOUNDQzBaBggrBgEFBQcwAYZOaHR0cDovL3BsYXRpbnVtLWcy
Lm9jc3Auc3dpc3NzaWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURF
OTVBQUU5REY5Q0NDMA0GCSqGSIb3DQEBCwUAA4ICAQAXV/Z7yw0Z0R7pZ3jQPbw5
r7KKLka8XZBV6l3PAsqxPhaWOkpNf7VbQE9sbKMCpqV9TdZ0wPMjekXS1Ii9xRbU
REz8sCKMlfQGtpiDzttKi88+ss79+1rulmIBWqBQN6ubf7b+LZjKroraLljv+Kp7
Z6vZ34lLQKRSCzNo8xg04/VtQwKfd8c1tMavtc0Su0R276wF8ix9Ddi8rmPBwmKv
jP/bCQwBVgFuVUGInFeUsn/S4svs5YjhCBTfz9Xsqx4riAyCDV+z+CigCTFk6GwP
lxoshOfC686DlYAa4oJVSCJ8wtSUos+yY696mv8Zn05Cs+De8zfxTxsA+yJW6t7F
uCh6vf3cULBh9PkmG2jGHu9PvMZ1JGp+gq3DqRUWhPYbsDUHT7vC7s9RYi5IPqTw
Qhsf5YdM/Uq5lrlu67sXKqBhlU8TXS76ESU+76SKJ1Ub3l1nWv9IcJfetC/fnZnb
+Wz5rst/qsWONVcWkY7DczQy0D4UUSsLcV0HjbsqotZyhGa+mBKBOKKC2c8pYYvk
lOIHTOiDpSMF+6S2UW0VVpdDqq4CKHRkOjEI8oySryww5Yf9A9Fkc+Ki6RZPwwoh
pQATKSkgGFB21zTtCa7+G3AghNAmPzPLGW6Ivx/NFVJgdzp3b4Dz/JROWShVmjAf
xrlvJs5aAyn240Dd8T7F0Q==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGwDCCBKigAwIBAgIQAOKjZ925iBlAqEheVUGp/TANBgkqhkiG9w0BAQsFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xNDA5MTUxNjIzMzZaFw0yOTA5
MTExNjIzMzZaMFgxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcx
MjAwBgNVBAMTKVN3aXNzU2lnbiBTdWlzc2VJRCBQbGF0aW51bSBDQSAyMDE0IC0g
RzIyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApgky7tyv+w2JirbD
l30lH5v4JrHDKwU76slAffIE7gy5FiX6EB08/FSAiWkULdkoacAAj8+9ZXOhUJAv
id+EVKqS5ccNAlZFTF8r2964fLgiia1MCauqQkyV5pzRAP8s5UzNcfeFw0WfSP6U
RirIHEHFqM6G7Up2Nv67WjzmRfSSN/x8womdSsXvSaXweYBt/PX4/Sl893f9UW9j
SPz0uUd7m5aW8/z/+vuJAOdSXVBWLi4hN2T9Dvgbuy0n5O0xc6wVnNvZB2fxbEaF
LBtJIWu6OcpLpNWFsfyTNiZ9SGklftD5pLWCgyeERuzurdnspdf09GtlSYh0VyZe
nOMDqQIDAQABo4ICkzCCAo8wDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFPCQTIvh8ALeAAFrmOfu3FGN20CuMB8GA1UdIwQYMBaA
FFCvzAeHFUdvOMW0ZdHelarp35zMMIH/BgNVHR8EgfcwgfQwR6BFoEOGQWh0dHA6
Ly9jcmwuc3dpc3NzaWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURF
OTVBQUU5REY5Q0NDMIGooIGloIGihoGfbGRhcDovL2RpcmVjdG9yeS5zd2lzc3Np
Z24ubmV0L0NOPTUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlD
Q0MlMkNPPVN3aXNzU2lnbiUyQ0M9Q0g/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MF4GA1UdIARX
MFUwUwYEVR0gADBLMEkGCCsGAQUFBwIBFj1odHRwOi8vcmVwb3NpdG9yeS5zd2lz
c3NpZ24uY29tL1N3aXNzU2lnbi1QbGF0aW51bS1DUC1DUFMucGRmMIHGBggrBgEF
BQcBAQSBuTCBtjBkBggrBgEFBQcwAoZYaHR0cDovL3N3aXNzc2lnbi5uZXQvY2dp
LWJpbi9hdXRob3JpdHkvZG93bmxvYWQvNTBBRkNDMDc4NzE1NDc2RjM4QzVCNDY1
RDFERTk1QUFFOURGOUNDQzBOBggrBgEFBQcwAYZCaHR0cDovL29jc3Auc3dpc3Nz
aWduLm5ldC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5REY5Q0ND
MA0GCSqGSIb3DQEBCwUAA4ICAQAwt+R/QMYqzRIatBxAcIQQpCkL18rYBfbFpPWA
X62JohEKCrhAVrrP3BFVG0qxtNSe2zgBBh5k48LQ1/FAhsZrw0+HTB9dvtyoTlJ7
IfO0EpiDy8g7i1sjCRNXVJM+sg4t5auyQ0UxdADHBJ4BXI/ie5JmwRicIyb18/ET
7+mr8jPbhvnqcumZndzhrxXiYznw9ZaXldB+BTRAaWnn2hURTVDJZhRRjazax8gX
U5FDbYPZizZbZVFY9zPr5FSaMEDo4T1NrXn/Y5J+Yj3J09qs4zdGvVJ8GiYFwBnD
CbrqzmQ+rZ+Aw6HjsmljVW/d0yMTwbLhr1QAfZQEYGzKPSU4WAbxMi4YFL6DbiWr
BuuJ38YjD+gnUcjb4bx6N6gOVxvm7ECiWsUdfS9+Ojtg1U5ijBOz8jgS2OhtR6Ax
FEDk5x3yw1IwwsMpY10Fng+7ugKiTMRTSkgxSWk143qpBGmSdulwqZTUA/YnENo4
1j/CX8W6TakZS0UoFq/dKmRqCYD+egF1AKy41TCotBOc2NV/Xr4W+uNEvYCD8yDV
qLghY1G4FHphXVrSEdmEeBqg6jAiRjOHgioCpZIrBSdwNH8qFUUvHtlMH4sJctnG
WZrqNoa5nl1wimrx4gjDRiKce2osH57v1BHHou2Cod4Bhqe7D6rqQcdjAnLen3O+
6NuVmg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG7DCCBNSgAwIBAgIQAPPCwxEohCnFb7b91aGD8zANBgkqhkiG9w0BAQsFADBJ
MQswCQYDVQQGEwJDSDEVMBMGA1UEChMMU3dpc3NTaWduIEFHMSMwIQYDVQQDExpT
d2lzc1NpZ24gUGxhdGludW0gQ0EgLSBHMjAeFw0xNjEyMTkxMjQ2MzlaFw0zMTEy
MTYxMjQ2MzlaMFMxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcx
LTArBgNVBAMTJFN3aXNzU2lnbiBUU0EgUGxhdGludW0gQ0EgMjAxNiAtIEcyMjCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0czicvr7jZnJiinLCtZWgg
zTsXP3tGhy+G7PLBhAspbPKh84g9wvDqxIGHJ0RnBJMEtNBfPqJeT/BbX/OoyMWo
xcPv5kRBBKAyWePpsFrtZgX7wbd6wZBTmAogswEEp8vTHCCSHud5H22Qlln1ort+
2OzZmZFKuTpvBoOf6eIDj/Pm58l3lkWBaERPS7HN0bxl+yqEgy5fO4bYKECKTz6Y
5Ve6qKhuVEWtMU1Qke2M+xJdDMz/aI2JxUGLHc45/eIIGt4DA8gWY8ItX26d8Vju
2Dryz2aFujnu+vTA/En1vQwpPJX2hPvLHQctsv5a7uS6GazGR+Dr1Dou/zcknxUC
AwEAAaOCAsQwggLAMA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcD
CDASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRw/lE40AnhYpO0KwNZ00Vf
MdPONjAfBgNVHSMEGDAWgBRQr8wHhxVHbzjFtGXR3pWq6d+czDCB/wYDVR0fBIH3
MIH0MEegRaBDhkFodHRwOi8vY3JsLnN3aXNzc2lnbi5uZXQvNTBBRkNDMDc4NzE1
NDc2RjM4QzVCNDY1RDFERTk1QUFFOURGOUNDQzCBqKCBpaCBooaBn2xkYXA6Ly9k
aXJlY3Rvcnkuc3dpc3NzaWduLm5ldC9DTj01MEFGQ0MwNzg3MTU0NzZGMzhDNUI0
NjVEMURFOTVBQUU5REY5Q0NDJTJDTz1Td2lzc1NpZ24lMkNDPUNIP2NlcnRpZmlj
YXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRp
b25Qb2ludDBuBgNVHSAEZzBlMFkGCmCFdAFZAQEBAQUwSzBJBggrBgEFBQcCARY9
aHR0cDovL3JlcG9zaXRvcnkuc3dpc3NzaWduLmNvbS9Td2lzc1NpZ24tUGxhdGlu
dW0tQ1AtQ1BTLnBkZjAIBgYEAI9nAQEwgdIGCCsGAQUFBwEBBIHFMIHCMGQGCCsG
AQUFBzAChlhodHRwOi8vc3dpc3NzaWduLm5ldC9jZ2ktYmluL2F1dGhvcml0eS9k
b3dubG9hZC81MEFGQ0MwNzg3MTU0NzZGMzhDNUI0NjVEMURFOTVBQUU5REY5Q0ND
MFoGCCsGAQUFBzABhk5odHRwOi8vcGxhdGludW0tZzIub2NzcC5zd2lzc3NpZ24u
bmV0LzUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5NUFBRTlERjlDQ0MwDQYJ
KoZIhvcNAQELBQADggIBAFcSVndW2gfSPIt474YTvC70phJPk2mXJqTTQkEfH6sM
mtaSaKtiA932E52wKfVa6RR3ORAAud6KVMUHkl/1O7uaM6Bmsi5/peHZVzsfxJCm
opDSl3y0uetW7nfOwIcDLbfOruBabEEUUFGv/q1dV3hCBQyIrwQ7HRiPtNb/q22q
E95jAKDiKpxO0fToD1e2LHxoVbUlqV4VFbN5DW1edEQHPXtozN/cZytk5Fhf9RtY
u0f42oJQv4YYEsFE3PRAEC0KrRQx2h1XcTufH0QqO01L6wUtdYlBoOb36wxAjAxS
ROM6Kv5hBpWo3d/p7qQcsbxhpfdBk2YT2ub0q+uKKng7At+c3oRq2bUgZ8KhEI+A
KgILb0ILeAIGGdHt6z5vPmWEjtGLkyvXbwqDyrDMI2gf2129pUgYqJHigmy3DNei
7DML2kCnBZ+POajNWvdPSjdYcaR9LhZkpiY0anUkUGWHRu/oNWdrKdYA71VvZQVM
2q+rb7jAmhuT0MLwH5/oPLwaQPVHBgA+pZsRbbxSQGqYFL2AwMUe03+n534Frvmv
wdrvZ9JZ26RA2Xv93GALQD1h71lEc8Dm9e4xrhNpJhPxFWtTNH7H0/eIZtSW2RrT
AAqVTBGF7riCJTJGpL9AnRo/uhfBEFfJcaqhQGXGIYqnX+Gvy0vbHCE5YD3T1n7y
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIHATCCBOmgAwIBAgIPZE++YXkt1Ge7IHl2cBCWMA0GCSqGSIb3DQEBCwUAMEkx
CzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxIzAhBgNVBAMTGlN3
aXNzU2lnbiBQbGF0aW51bSBDQSAtIEcyMB4XDTE3MDIxNDA4MjkxN1oXDTMyMDIx
NTA4MjkxN1owczELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFN3aXNzU2lnbiBBRzEt
MCsGA1UEAxMkU3dpc3NTaWduIFRTQSBQbGF0aW51bSBDQSAyMDE3IC0gRzIyMR4w
HAYDVQRhExVOVFJDSC1DSEUtMTA5LjM1Ny4wMTIwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDBpZZYwGuWDP+hjeI/On1GwJse/bRaXtr0QiVM81joYx7C
qetjjjSsBLEsg6ibOxVsEsEDXU6XvTb7bnp+eecO+221Tx+5gUSVdCGcDXFeuFr1
6w87VL+RaMqonkcywo1MDyHjTwVJYq71PJ2Q/MjAahZ5WD7Ufma/ucTpoch6gDYK
xU2xF/zFFKa51C+BzPEYEmqlQirNrk6ph4umEXZOLisG5o5TrrpE06P1VscIunsc
cmwkXXELP/RXjAbzvwPT1urOmi1dUnPBJK30xk/8b3j4taLJoWdauK8gYMi1FPYe
aQ0agmUBuUaC2ant7LzhqE0nL1FVo5AV4emK2JMBAgMBAAGjggK6MIICtjAOBgNV
HQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwEgYDVR0TAQH/BAgwBgEB
/wIBADAdBgNVHQ4EFgQUW81v0+ncYWCDSyEqbXAKfbaDe+cwHwYDVR0jBBgwFoAU
UK/MB4cVR284xbRl0d6VqunfnMwwgf8GA1UdHwSB9zCB9DBHoEWgQ4ZBaHR0cDov
L2NybC5zd2lzc3NpZ24ubmV0LzUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2NUQxREU5
NUFBRTlERjlDQ0MwgaiggaWggaKGgZ9sZGFwOi8vZGlyZWN0b3J5LnN3aXNzc2ln
bi5uZXQvQ049NTBBRkNDMDc4NzE1NDc2RjM4QzVCNDY1RDFERTk1QUFFOURGOUND
QyUyQ089U3dpc3NTaWduJTJDQz1DSD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0
P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwZAYDVR0gBF0w
WzBZBgpghXQBWQEBAQEHMEswSQYIKwYBBQUHAgEWPWh0dHA6Ly9yZXBvc2l0b3J5
LnN3aXNzc2lnbi5jb20vU3dpc3NTaWduLVBsYXRpbnVtLUNQLUNQUy5wZGYwgdIG
CCsGAQUFBwEBBIHFMIHCMGQGCCsGAQUFBzAChlhodHRwOi8vc3dpc3NzaWduLm5l
dC9jZ2ktYmluL2F1dGhvcml0eS9kb3dubG9hZC81MEFGQ0MwNzg3MTU0NzZGMzhD
NUI0NjVEMURFOTVBQUU5REY5Q0NDMFoGCCsGAQUFBzABhk5odHRwOi8vcGxhdGlu
dW0tZzIub2NzcC5zd2lzc3NpZ24ubmV0LzUwQUZDQzA3ODcxNTQ3NkYzOEM1QjQ2
NUQxREU5NUFBRTlERjlDQ0MwDQYJKoZIhvcNAQELBQADggIBAK9TgFoIW9W4Krb2
QnjGhjwfE37GkWOaiMuBWDr34MFGAKnrP2XMtrOpVwTlkOK1yXt8r/2epxF0LEGB
+IW72ogAasNiVXzAjMNb/yopmhPC1vfC6jYrXdrLc+K6BJW24jwoXk3v8mFkghT8
abS+ArQwUY/RaeRZd78svd9GwiiK91K6Rqa1PmdONAb/hM0Rq/OGIatscbf7LSWW
SOSzt095q2r6p6U4EckzlXqfi+OGDbzqp5/j4DZ8UM2FTOdMvtiz4cGGuTKreA6a
7wXPOKzR8Du8FtVVM8JLMsxEZF7Mytu6iC8tS8h6A4jKcbs8KHdVEp3Pnwp5io6t
hQ9Q0f4zkRyZVVyNcbuvaRYfYlP2mRjgWu2RyPsFp5sXsIcE/0D2NiPVXDpHNp55
oF7ppb1hK8/CRwXnnh+PKelvGJ+NH/inKMWzjVYC6xtSB+CX2ahFxB1fgdhSLS/R
GlQba/At8YcxNWiUzX3uzTQ3Dqi/ADu7qfAIGmpNpw6RdvwqwX+dYYT6Pv6jcPyW
InFyypgJ9kS/yYX3l7D2eksMUT0xWc1CARjpWVs7oInLY6b3obefRiuRou4JNCrh
t9+s8UW5XVPVVlIfgtcf6Mba17T8my8m6G9vC4QOevojTil7AYMcSLtA2W3Ffxnk
p2zvs82C74Q9qYtytpiklrI/0bLC
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGZzCCBE+gAwIBAgIJAOJWt1OXa3ZYMA0GCSqGSIb3DQEBBQUAMEcxCzAJBgNV
BAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxITAfBgNVBAMTGFN3aXNzU2ln
biBTaWx2ZXIgQ0EgLSBHMjAeFw0wODA3MDkxMTExMDlaFw0yMzA3MDkxMTExMDla
MFUxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxLzAtBgNVBAMT
JlN3aXNzU2lnbiBQZXJzb25hbCBTaWx2ZXIgQ0EgMjAwOCAtIEcyMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9/NTXkltjAPlJxchGGCldpQ/FRC4IUDP
NjOsKnKaj2HDa956SQhYPYDYO/CdHUEQAb9rB1YajbM9v2O6MX7ickYYaIfXhU+g
yXsTqdA50YnWNWdodsFflgnNzzoF0T8GBQraFvJD8qQHHaKsgHUBnaDo9zSnv7bm
OWhmUkc5KU20negqrRVhtKIx4BCR2x7kQ/Er3hDBNMtshO5iFCdE2DHx3zwhzMCs
kGjTdGjJF0qOOwmnsQVljQekkK4uet56RG+wAv50/xqH9VjppiXxzIgiJ9jLMcEv
KAxxch73+whObnoFrCF/PwpaZvi/5RYU+RubxJ+6Mw2GlxVdrqEGjwIDAQABo4IC
RjCCAkIwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0O
BBYEFOs1sVZtFWBY9OEizRxGHK7QBABlMB8GA1UdIwQYMBaAFBegzcHkQbY6WzvL
RZ29HMKY+oZYMIH/BgNVHR8EgfcwgfQwR6BFoEOGQWh0dHA6Ly9jcmwuc3dpc3Nz
aWduLm5ldC8xN0EwQ0RDMUU0NDFCNjNBNUIzQkNCNDU5REJEMUNDMjk4RkE4NjU4
MIGooIGloIGihoGfbGRhcDovL2RpcmVjdG9yeS5zd2lzc3NpZ24ubmV0L0NOPTE3
QTBDREMxRTQ0MUI2M0E1QjNCQ0I0NTlEQkQxQ0MyOThGQTg2NTglMkNPPVN3aXNz
U2lnbiUyQ0M9Q0g/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
dENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MGQGA1UdIARdMFswWQYJYIV0AVkB
AwEDMEwwSgYIKwYBBQUHAgEWPmh0dHA6Ly9yZXBvc2l0b3J5LnN3aXNzc2lnbi5j
b20vU3dpc3NTaWduLVNpbHZlci1DUC1DUFMtUjMucGRmMHQGCCsGAQUFBwEBBGgw
ZjBkBggrBgEFBQcwAoZYaHR0cDovL3N3aXNzc2lnbi5uZXQvY2dpLWJpbi9hdXRo
b3JpdHkvZG93bmxvYWQvMTdBMENEQzFFNDQxQjYzQTVCM0JDQjQ1OURCRDFDQzI5
OEZBODY1ODANBgkqhkiG9w0BAQUFAAOCAgEALip22pfzTN9kJ+FbLZXvuVUu27gJ
ZTFAsEu9fJCx2dhxGFPO6DUsmxS6H3SC1FeSwFeTm1AFJXvgldRduER46TOQQf7h
v0abeX1yvDhQGcBoWgay0xveXWfPaZL49awJhdTdWi5qOSPv9O9zWjYew+mNIEdk
Nx85eRPXDlCyrLoZnuqD5EVGBL7NLzkQCJsNifBVsiYkUbNr0XxpPVjVgTU8aEdX
jcYSs88qahVFL4SpTj3BOcrr+95KnK0buGGWBiC4gCMZtHZDHJ+umjheENI49R6e
2QwR1S74yYqHpwyz0ihdI2xOZgXxmGOg3GKBxEficqLgbRl+PV2FRZdogAOl8PXt
25iCzummltrfbjXaGQNg9rBHmAM05bxgtMCQwCj0BG48ufpJhzplOLS1YYIehiHv
mojFdSg1q15SYC867zGLpnv3SAxwPLXXYsu0QsP0jbhEcYwk/NfunyHoqmOWw88H
W/KB0ppwJ1QYzO6h0Qwijl7QmUM5qlJOZxuP2jK8WoOS2jarU3r0EXfq/Nfo3uqX
xm5QDg9E4M8wyouaoaCn/LnoxS3zc/VU/p0o15AjIylPSTN/kHmDSl4eYZFmBBhd
0YhvjC4hW2UBRM12SQAAEPIaEqUdxrYFfogWojYCoymheKskXfAKdA1k2gp5mhVh
SFXeRgS5uQTbqpY=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGvjCCBKagAwIBAgIPBUTWTq0e0zbVMkBdALk2MA0GCSqGSIb3DQEBCwUAMEcx
CzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxITAfBgNVBAMTGFN3
aXNzU2lnbiBTaWx2ZXIgQ0EgLSBHMjAeFw0xNDA5MTkyMDM2NDlaFw0yOTA5MTUy
MDM2NDlaMFYxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxMDAu
BgNVBAMTJ1N3aXNzU2lnbiBQZXJzb25hbCBTaWx2ZXIgQ0EgMjAxNCAtIEcyMjCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMs5sTmF/vrJobzDg6kOSi2E
ch7/aMWnxB3sD9eoixMes9EWi0DcD1NvAT3s6GS1l9uDvKiowIQ4WF4DFCvmyjDv
ALLrEzkZkkcqIQDlcs3CMWIOzFYq/3fEY4yYwm9417W2zOl9HzOmkQUq/tFS1vTs
nP5NTGpS4YV2Yru5aOZSY/zBIZGSXRnY3IDRGeNJFlcCDhlEhaspyS/6xm1rCqH2
9/9rYTUVJpSUAmklXWn3vV5rgtmQDAb5QwUiSes20CBaYxDjOCHVfxYrQYpGevJn
6KTQuh5/JCd1mJRJLVbEVDORnWL51V/eW6kVmJyUU8GA6QkXFbQbgCkyodCvE6cC
AwEAAaOCApYwggKSMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEA
MB0GA1UdDgQWBBTwx6MykbXryrVYdxWnTr4aXWFDJTAfBgNVHSMEGDAWgBQXoM3B
5EG2Ols7y0WdvRzCmPqGWDCB/wYDVR0fBIH3MIH0MEegRaBDhkFodHRwOi8vY3Js
LnN3aXNzc2lnbi5uZXQvMTdBMENEQzFFNDQxQjYzQTVCM0JDQjQ1OURCRDFDQzI5
OEZBODY1ODCBqKCBpaCBooaBn2xkYXA6Ly9kaXJlY3Rvcnkuc3dpc3NzaWduLm5l
dC9DTj0xN0EwQ0RDMUU0NDFCNjNBNUIzQkNCNDU5REJEMUNDMjk4RkE4NjU4JTJD
Tz1Td2lzc1NpZ24lMkNDPUNIP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDBhBgNVHSAEWjBYMFYG
CWCFdAFZAQMBBjBJMEcGCCsGAQUFBwIBFjtodHRwOi8vcmVwb3NpdG9yeS5zd2lz
c3NpZ24uY29tL1N3aXNzU2lnbi1TaWx2ZXItQ1AtQ1BTLnBkZjCBxgYIKwYBBQUH
AQEEgbkwgbYwZAYIKwYBBQUHMAKGWGh0dHA6Ly9zd2lzc3NpZ24ubmV0L2NnaS1i
aW4vYXV0aG9yaXR5L2Rvd25sb2FkLzE3QTBDREMxRTQ0MUI2M0E1QjNCQ0I0NTlE
QkQxQ0MyOThGQTg2NTgwTgYIKwYBBQUHMAGGQmh0dHA6Ly9vY3NwLnN3aXNzc2ln
bi5uZXQvMTdBMENEQzFFNDQxQjYzQTVCM0JDQjQ1OURCRDFDQzI5OEZBODY1ODAN
BgkqhkiG9w0BAQsFAAOCAgEAw3mnV7d7rVFo9USMQZUoAXx01jtqvG3vp9dNOZkd
aI3KCNnQcbEZNZNvgsYcSbhR7kz5bApv2KX7/vswXgDSlKvEElG6qoqrat0Z1ytK
9xaya1HPdFsponPel/7YTyAhfWkMsFDljViMgC7lFxzdY3qq7wX5w2me5IxxYlxC
7jryzeAS74tc6c5TKDLslQsZVKIhjfp/UKdPvBl7smuMKT93Psojx2laQZ19ZjFv
enF52qllOut/1xDVC19UGXzONyUkhFDQr0A0wl+S4nqR8y9CRxufPEL72V+lvHBF
ju+gOZD1oXhs18BnWRnhAN5c/HjoT927rJEucov86kdvQyi8u7mOlL76UN1QkxtM
GLZ2/8NHClm0zW1V2Gq2X8kvwZQ2Pr6uQDUGIO3gAkwtNEUOQ6+i9NiQFeXQwJtE
QK48j5NRvJloc2l7dViZt9QET9/xgnERHXv8Ex13ZVVj11JyfN0xR4anldisJnE9
I+YSO/R/mpaG/ivqoPMmDXXGFowxIOcRR6HnqWqwpbKBHtw90KHjbtXwZqYcfdeS
iE0ABwtx53Pnc+RUZWn8N43xHm9w7qdss1JFZ1nWBUixIemXKNnZ9LSmoGcjNrxg
Rw5cKH9dk4oxuo0xNhTHekKdbyDBbCr4Fg9q2QCUMrs9VbHFw6ENsXl3VB3gM4J+
7uo=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGvDCCBKSgAwIBAgIPa8MYySrNF2PrQchvr0f3MA0GCSqGSIb3DQEBCwUAMEcx
CzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxITAfBgNVBAMTGFN3
aXNzU2lnbiBTaWx2ZXIgQ0EgLSBHMjAeFw0xNDA5MTkyMDM2NDNaFw0yOTA5MTUy
MDM2NDNaMFQxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxTd2lzc1NpZ24gQUcxLjAs
BgNVBAMTJVN3aXNzU2lnbiBTZXJ2ZXIgU2lsdmVyIENBIDIwMTQgLSBHMjIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDokwjmGAGzVxkPTD8FLdUerBu4
nCwsqp+VK5g3NYSeSAOBGTPoY/YueIkgmjvIfBov2rjhOl5a7oOX2ymM8/hv/99n
DxLgi6X6N2+B1MgKcQ0/3KZW5NOI8Ym46nZOjGt3mdMYNf9ORWTXIYLY7skjbLxD
qXS6FvrcQrR8A6y5btxyD6jk9KXFpfqHRL9ZdbeBRyPLmOUOHdMqu/8xk6UBeyFo
jXRA5wXNZyNkoDvzujGjozOvvWrNYUCyjCoFbrpX/vORJAc8bUONzYWNnm4cFfi7
TG7yKcUkSBp5i16q3G1emHNEDiscX05LlCYVeo/WOriSthL7Q03FJEMO6D5FAgMB
AAGjggKWMIICkjAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAd
BgNVHQ4EFgQU27y/ghhZ3Gn6+Kuqg013HQuwi9gwHwYDVR0jBBgwFoAUF6DNweRB
tjpbO8tFnb0cwpj6hlgwgf8GA1UdHwSB9zCB9DBHoEWgQ4ZBaHR0cDovL2NybC5z
d2lzc3NpZ24ubmV0LzE3QTBDREMxRTQ0MUI2M0E1QjNCQ0I0NTlEQkQxQ0MyOThG
QTg2NTgwgaiggaWggaKGgZ9sZGFwOi8vZGlyZWN0b3J5LnN3aXNzc2lnbi5uZXQv
Q049MTdBMENEQzFFNDQxQjYzQTVCM0JDQjQ1OURCRDFDQzI5OEZBODY1OCUyQ089
U3dpc3NTaWduJTJDQz1DSD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/
b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwYQYDVR0gBFowWDBWBglg
hXQBWQEDAQYwSTBHBggrBgEFBQcCARY7aHR0cDovL3JlcG9zaXRvcnkuc3dpc3Nz
aWduLmNvbS9Td2lzc1NpZ24tU2lsdmVyLUNQLUNQUy5wZGYwgcYGCCsGAQUFBwEB
BIG5MIG2MGQGCCsGAQUFBzAChlhodHRwOi8vc3dpc3NzaWduLm5ldC9jZ2ktYmlu
L2F1dGhvcml0eS9kb3dubG9hZC8xN0EwQ0RDMUU0NDFCNjNBNUIzQkNCNDU5REJE
MUNDMjk4RkE4NjU4ME4GCCsGAQUFBzABhkJodHRwOi8vb2NzcC5zd2lzc3NpZ24u
bmV0LzE3QTBDREMxRTQ0MUI2M0E1QjNCQ0I0NTlEQkQxQ0MyOThGQTg2NTgwDQYJ
KoZIhvcNAQELBQADggIBAL9A6sPv+erbRxhzA79b9B8tUFy6cggOHqHHzxDnsFbC
UIL98ajLjHdV7+HfKNkNkXxhqIXvbG9Ak2CmF1x1dJtWiWmGRir7BstpcqoAI4Se
P2rwGcarCCbrHmpey+5OvdCaPFMJLO1tk/0vukIGMd/dUiceIFN5RLgatbBtgDo9
NKl/GCZE4Ltyz95yILLU4FHUR+VEA/LjEnP/3M+JqoqnvQ77DYmWPVLRGkwKizFQ
Xz/1/lYeNr/0WMpPpyvEAA7iMpP2bB1yGr5K8KPnCY82Lqnb3yB2BKIg+gbj4QNQ
ifybp+gCu/IYWWWfVHVAqYQurGYBai7wYvYCVedhqRAl/Xh5ny3CiWpKNrce09X9
u/N3kBefCMH2HEipgJAx+2t66Qw+4H70TV/nJoB3w9eTukKRqpDNebdYBR325QHI
fiQMc4hs12TLDmpL3tAGdpsKx3/jBfz4qLrr36ZPNO0ost6OCyJH5rsn/ctq6Noc
OjMTfJLqZXP8DKVSYRCRxFesNxQXRROx1HfGJus0gB/x30A3c2L6IvKOV+qQgidf
vTy3FMK1j4toytXiaafI+Caus+GbmDMCtsEQiwxsNS4HZCVXZXGr84lsfK55CNg8
84npHRtOijniyemc9gsTkT50zf8MkhmSdXo2MJuP2rX7A/WuV2FikJw+O4jRYWeI
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEuTCCA6GgAwIBAgIQAp7/0k8LfSOZNZubH9bz3jANBgkqhkiG9w0BAQUFADBs
MRMwEQYKCZImiZPyLGQBGRYDY29tMR0wGwYKCZImiZPyLGQBGRYNRGlnaUNlcnQt
R3JpZDEWMBQGA1UEChMNRGlnaUNlcnQgR3JpZDEeMBwGA1UEAxMVRGlnaUNlcnQg
R3JpZCBSb290IENBMB4XDTExMTIwNzEyMDEwMFoXDTI2MTIwNzEyMDEwMFowaTET
MBEGCgmSJomT8ixkARkWA2NvbTEdMBsGCgmSJomT8ixkARkWDURpZ2lDZXJ0LUdy
aWQxFjAUBgNVBAoTDURpZ2lDZXJ0IEdyaWQxGzAZBgNVBAMTEkRpZ2lDZXJ0IEdy
aWQgQ0EtMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALoLTRpS0mNR
MRmmpWoAdtLhgpt9IQwTNnzM+lINbQPvSoQm4RQEYLYmDBCZnF1EV6YOKHEivuzf
cStmQ/7YI51Phyma5/Siy4glgu0+JiugeaQdakysESZKu7STFtg5dFZywL5vIWH8
B44pdce4TBrC+a6sjoP7+1DdsOM1CAVz3gjpUcbJdbZIOMogYVwCDIedgwTWd2NY
d9ZP+QwIXS8D6aa0ehdyIDLJUXEtADIBq/IbD30qz3MC2unkL6npk3yOpW4YWSnS
veIqcUhwq8QE+bxQBBbgnKmfH4WenyKzaiil9OtHC0hjDngGIhIamRskfG2TyGT7
aXBDZkqUJnECAwEAAaOCAVgwggFUMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0P
AQH/BAQDAgGGMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29j
c3AuZGlnaWNlcnQuY29tMD8GCCsGAQUFBzAChjNodHRwOi8vY2FjZXJ0cy5kaWdp
Y2VydC5jb20vYWlhRGlnaUNlcnRHcmlkQ0EtMS5wN2MwdwYDVR0fBHAwbjA1oDOg
MYYvaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R3JpZFJvb3RDQS5j
cmwwNaAzoDGGL2h0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdyaWRS
b290Q0EuY3JsMB0GA1UdDgQWBBTvsHWdaDHR5PcqiYJTnTl3aC4gUTAfBgNVHSME
GDAWgBQ9yNSzuaF3UJdQEVCoOeUcU2PGcDANBgkqhkiG9w0BAQUFAAOCAQEAZixh
Zm0WtmCCR1vnouUSorR+S8WDhZk9c2xpslHsdWaO2pYb65aGpoit8IUQ5VaehH05
GHAvAWI/Jnga1GIHQFbPUSYbG5eJcUh/XKEqdGYG39kjNXsFzS2wncFbdA3HiKAr
78Q8cNvuTjS/HFthRfnwZmYA7am0BaXuF9d5YkzSspxRBUbLGAnvudicXVPOWx2p
my6M6/Y/rTIhzdH2JEzFxG5q598FWyR4BY7XhUrprii7kkbAr9EA35fKZ7IWhk/0
viAoT4LnGWrGK71LcJl1UdZD7GuPp4hGmrf0ReXUiqXzLD4Yt88LR95Xecx/K8Wt
2mgPG/cieHl9M/NZ/g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEvDCCA6SgAwIBAgIQDDLx0Sp02Aw8WPQjYJtoXTANBgkqhkiG9w0BAQsFADBs
MRMwEQYKCZImiZPyLGQBGRYDY29tMR0wGwYKCZImiZPyLGQBGRYNRGlnaUNlcnQt
R3JpZDEWMBQGA1UEChMNRGlnaUNlcnQgR3JpZDEeMBwGA1UEAxMVRGlnaUNlcnQg
R3JpZCBSb290IENBMB4XDTE0MDEwODEyMDAwMFoXDTI5MDEwODEyMDAwMFowbDET
MBEGCgmSJomT8ixkARkWA2NvbTEdMBsGCgmSJomT8ixkARkWDURpZ2lDZXJ0LUdy
aWQxFjAUBgNVBAoTDURpZ2lDZXJ0IEdyaWQxHjAcBgNVBAMTFURpZ2lDZXJ0IEdy
aWQgQ0EtMSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALCwFRVh
i4CR3PGtTVjHnyrCiBoaW5VUbMxEJDDfdXZLWmb1arm29gCTdd/IVIiur22dID8h
iiEvJbLEN6ikKrYJyrQzwmTYNXSwIaKNNfYRWDQS1i2aEHykE1+81IG5qgkUaWPJ
dy1mI7n+BHLHucN25M1CLT695R1ulbA7pcboKc51aVI0r6HqYtGWiNpum/Jlw2el
QScJak9NoPEuMk+kPQH+c4gMzL+yMRwDqNGn3Xx4Dm9Ju9lwgM2Drw98iA+s4DnG
P1FppgxVx7PTNZzYLhmbVxTLMp34AE22O4iY02/zd8PRAlrNHP7UhTopIfCB+GPr
+Inkt5fj2KNqHzkCAwEAAaOCAVgwggFUMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYD
VR0PAQH/BAQDAgGGMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDov
L29jc3AuZGlnaWNlcnQuY29tMD8GCCsGAQUFBzAChjNodHRwOi8vY2FjZXJ0cy5k
aWdpY2VydC5jb20vRGlnaUNlcnRHcmlkUm9vdENBLmNydCAwdwYDVR0fBHAwbjA1
oDOgMYYvaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R3JpZFJvb3RD
QS5jcmwwNaAzoDGGL2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdy
aWRSb290Q0EuY3JsMB0GA1UdDgQWBBQ2WczfPDriSZNPJRJCts/pGR8ytDAfBgNV
HSMEGDAWgBQ9yNSzuaF3UJdQEVCoOeUcU2PGcDANBgkqhkiG9w0BAQsFAAOCAQEA
a2miBJ5shp9VaF8n9IrLxwzxjT2Kg4YzmsQxuP+kicHOBVaa5njakpnjYMpQ9M3k
Wd4L1EAsJ6v06SGiwizzbzo7fCGpUqwlqm7clf7MBKmuIktDuBfV9iSDccg4hIcL
RCJ4WMibrqKIj57Iia3jCxzvHW9kV/KfP3+/JsIBzhQYN1I8Rbb3XVBil5bhBtYU
/Nxw7TA5wqaDhkoGxCAlOhfizB7LHkzbDckmzqoo855g3NJSZvk7OpE9ddoXNFSn
deCCG7oIYBiK2NH7O73Vtgf2d+pHfrj8Z3ZnB9JmjSacRcXldZSNzd5T/S1VIz80
GH1fIzyIXztGhqw+eW9OAw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIQAmE4fDe0OaWE+qFSUtrI6jANBgkqhkiG9w0BAQUFADBs
MRMwEQYKCZImiZPyLGQBGRYDY29tMR0wGwYKCZImiZPyLGQBGRYNRGlnaUNlcnQt
R3JpZDEWMBQGA1UEChMNRGlnaUNlcnQgR3JpZDEeMBwGA1UEAxMVRGlnaUNlcnQg
R3JpZCBSb290IENBMB4XDTExMTIwNzEyMDAwMFoXDTM2MTIwNzEyMDAwMFowbDET
MBEGCgmSJomT8ixkARkWA2NvbTEdMBsGCgmSJomT8ixkARkWDURpZ2lDZXJ0LUdy
aWQxFjAUBgNVBAoTDURpZ2lDZXJ0IEdyaWQxHjAcBgNVBAMTFURpZ2lDZXJ0IEdy
aWQgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL1Yym5/
MKraEAE4RKX8Suurhv5isaeNW1GoQV+jCo1fN0DEXWG/SBW27OIJ1slHI3pp68+j
pzdzpB7jJ7L25vgkIhKyUvf3VYqFRvdnVCouC3OIknilWO1J/spASh6/BS8tD2Z6
PE/n/NrqMkF6lZZuQuSooicEZkcxCmyM2Vp7XQXe+qCzILYsp5rEX4FXclT0SMiX
jVSlR+qKNhinecW6IW1mqSluMY9k/3ze5KmdjnhivJ+EKt9cUk1zMxSr//KjV7XA
d4IiQn3wi9sTWCdokVoVTrmMmksVYcjeq3Xcod/LiziqyqHo+c6uMSN5c3Hg2X1O
xU2UYWPIE1GQ02kCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAYYwHQYDVR0OBBYEFD3I1LO5oXdQl1ARUKg55RxTY8ZwMB8GA1UdIwQYMBaA
FD3I1LO5oXdQl1ARUKg55RxTY8ZwMA0GCSqGSIb3DQEBBQUAA4IBAQCTaCdkxfOe
gOJmMqoklLIqhaqbuH1D5RDzSsXET3iDABtxbcbuFr8LHEROICWOWVZi3VQih+f1
80wXqRaD8BkCpbKFzFMWCuOUmN5307v06gIjUAfKKyJumdI2WDaHcj65GAU17vdO
l8bP35sBNaO+O2ksL9XQfHuEdmkyi8UcdlkG9jQvsV89oMVcom8C7ATDUV7vpGEM
+teq7zkw8r6+VzJvNrfykPOLavN/gkKJwlAfa0muPi2E7uxK85059jwSc9ucpyaF
H/O8BdLIR2z2UmsAbnraQFMWS0SFvFfUH0BccrAEJ5RvLEMlXBy9haeNLTua7May
2amGScIUFi6R
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGgjCCBWqgAwIBAgIQBxVWH+V/ML4XiYkjwzpEUDANBgkqhkiG9w0BAQUFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTExMjA3MTIwMDAwWhcNMjYxMjA3MTIwMDAwWjBhMQswCQYDVQQG
EwJVUzEWMBQGA1UEChMNRGlnaUNlcnQgR3JpZDEZMBcGA1UECxMQd3d3LmRpZ2lj
ZXJ0LmNvbTEfMB0GA1UEAxMWRGlnaUNlcnQgR3JpZCBUcnVzdCBDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAO65BA1JPUZvUOjZf2SNLymSrF3vhYGP
XyfUHmsZcgUSZFuwJXhWJMiDkwk1NfQrk0Hy9CyfFAD1z7EiQgOMWWuWQdweBJxw
IzK/HQS0nTEwxEqF8O5cAWH478iZbY5sbTn9m5ZmFVRwPp1nh2k0c2mQ50QR078C
sAnuzpbzA9nA3uZAX8+txpfBQ9bFsTociALeIYR0FhvHh/RlvLtfHFnxpg6Q/n0r
AL9HKEYD+qBaBXtval0ziqRdr0B0yJ/d+inclJVKc/uNxrEjew9nbNMFnaoZ0Nt9
5uzn3qanjLxNmFRwBtvrA6iuJBlZlTjB1RpPu58l3TJ/LniIGPiRGHECAwEAAaOC
AzAwggMsMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMHkGCCsG
AQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t
MEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl
cnRBc3N1cmVkSURSb290Q0EucDdjMIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8v
Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqg
OKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
b290Q0EuY3JsMIIBxQYDVR0gBIIBvDCCAbgwggG0BgpghkgBhv1sAAIEMIIBpDA6
BggrBgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBv
c2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAg
AG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBz
AHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABo
AGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABo
AGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBu
AHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAg
AGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQBy
AGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjAdBgNVHQ4EFgQUYZek
mymYAZta/4fmdO8wg8xotMgwHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNt
yA8wDQYJKoZIhvcNAQEFBQADggEBAJtEamzsGt7a292/ds4LkJjwyRZ77QcYBns4
yXLuacEmMURsVXABhXcPGLtiy8h3slNSyB7V+mMrpXC1iPRGTSdOlHrkanyqXfDS
pjOX1Jn0OtDvLRbHybsI08XIoZCI1SRskt/COlRTfVw7HFOXcsxtN4EvYRtbK/dN
Z1zA8uqKPCXGVVhLEzlvoo8OZVVfKGPwqsaWi4SBjZNKWQklB8Pdezh0hOpLwUs8
Mi2YeJSxpfDTiJ5VDAAf9IIMnPouRQcx9KSNQqPAU2/jBt+9k6QpdVqIeC7ZP8Hp
7RdacX/aLOhgTNEwj3Aqgk6RYF8n+xUQe+AOylpgO+zovEWsBWQ=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFATCCA+mgAwIBAgIQDglHG7EZWmErtKS1sO1WCTANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQwMTA4MTIwMDAwWhcNMjkwMTA4MTIwMDAwWjBkMQswCQYDVQQG
EwJVUzEWMBQGA1UEChMNRGlnaUNlcnQgR3JpZDEZMBcGA1UECxMQd3d3LmRpZ2lj
ZXJ0LmNvbTEiMCAGA1UEAxMZRGlnaUNlcnQgR3JpZCBUcnVzdCBDQSBHMjCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMsBrEAAXJEFhz/RP7bYE8g8OdVe
EOwjrxmg7pXark39WKA7kS10ZPGYaE8W5/mv05ztMgA0J9vym+ZUtfOadVy/JNiH
jKZyiauxkh3TCjQhLfb+5fLQ3/XW8YylNzwcTAlQ2/eEaU0KXJmveXYh9+txcrWI
m/aIeHo5r8bpgi31jLRWFKeTdmoMQ3JX8sR5Zn9wuaYjokf3tiufCpF6h1lAH27F
xTkW5zkZ1RvdcKPnYQPPwquNIT/zIHb3QPNOOB0K0SDc1dPlWjWKeRgm/V7SBFvy
TFcj/zxHP8m5mh8D75jsW1AAKh8tnALFZxva5rr9RiHmwmd+mDsEYAt/eVkCAwEA
AaOCAawwggGoMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMHkG
CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
aUNlcnRBc3N1cmVkSURSb290Q0EucDdjMIGBBgNVHR8EejB4MDqgOKA2hjRodHRw
Oi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3Js
MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
SURSb290Q0EuY3JsMEMGA1UdIAQ8MDowOAYKYIZIAYb9bAACBDAqMCgGCCsGAQUF
BwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMB0GA1UdDgQWBBThZRoC
A5F+15ZtOIiLnhaRaxFsnjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
DzANBgkqhkiG9w0BAQsFAAOCAQEAKHBUklU69o1g8x7KNsso5ujW+S6Fw/AXLCCr
1aqkUTQ32hyJjVB0/AOnTIi1lCDKPYXdUDj2TIL9fxsSuj2GxGFEWTz6kW+gyKae
MvDJifY4TXmx22Mja4DwBjKgUggzvO5Vmf1gz3IZjv67D9SU0TLOhjbcYWKYu19/
+IDLmwV637KkjUgM1asqqtkutfT/d1+j4COTDWSD48OEOk8BiB9Rh+c17Af3yvRV
f90aa9NEStSVevR2h9i9rDrleeGNiKqCInvDa3szREdsT78+l4nITWH6os/iZnI+
4int+r0ifHJjNfL1b5NAxey8kIfNCESo/RnqktuXNptd7reo9A==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFBDCCA+ygAwIBAgIQDLagvlAOP6QGtXVwDg/+bDANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQxMTE4MTIwMDAwWhcNMjQxMTE4MTIwMDAwWjBtMQswCQYDVQQG
EwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFt
MQ8wDQYDVQQKEwZURVJFTkExITAfBgNVBAMTGFRFUkVOQSBlU2NpZW5jZSBTU0wg
Q0EgMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMpYsx0hE/klfhLT
BNrBXBA9fVAFiSjl4alcdS4N7hzZS72EA+/ViQQaN6jU2X/xvjP6DfrUGXbgWBmC
4vFBZkgVxaM3amHQP9rJ0MaQ6NXmRhiPuDFD9TaXTqs4q71wpkVaJwbZuROq9fwy
ZTofePEksl9jcg8CdkKLR6nOSmZyPUx0TuUvjEYCwjkRtZ3u0joIeabWO5+7ZOzq
pXV7pdzWGv/7V9wm86FweMzMDFvecNeiNtPGh/g3nQLAOwDZJd2oVQINIw5Qohub
eiF4//VY+1XpVG0y4etxpj9QNxJtpBQRnjgFy3MForsd2zpTXj7KyX/bKUYNGZFI
B7QhJp0CAwEAAaOCAaYwggGiMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/
BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
ZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqg
OKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
b290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNl
cnRBc3N1cmVkSURSb290Q0EuY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsG
AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMB0GA1UdDgQWBBQp
qhtuMPkwZ2OlhyYMrPGBnGl0STAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd
823IDzANBgkqhkiG9w0BAQsFAAOCAQEAp5f8mAuKmxksInIi5q2HM3UvKUzbWXN7
YBOUA2FRm+5bXWRiyJduedZ1mzsiOyzZLVU4P4DTL24xzdCt4aOyB8wi/ivCwUWW
4uAgh3iDd6eG+XWV4uao9dXy3Hz+pkxWLJ/YR13qn6LU2m7Jmri2gsYGIxCWBd98
jF+IEWjmstX4yXlMIEx5/seK9HoNnEnjYY7ycDF2qr+lE+lETt+csHL5xv05hzIZ
/yhEX/wN5BkNZJQedhgKCg3OQow6tUTPjgnQLMvcLbGAmTIWoiEpc+00Q0tZWR48
1cUR0MF0J3TDbY0q8pP8jJ/YHKofUNyEFEoS0q/4+eC34bmTWuKoqA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFCTCCA/GgAwIBAgIQArfJ3a3SvQnrWcRckAxgeDANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQxMTE4MTIwMDAwWhcNMjQxMTE4MTIwMDAwWjByMQswCQYDVQQG
EwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFt
MQ8wDQYDVQQKEwZURVJFTkExJjAkBgNVBAMTHVRFUkVOQSBlU2NpZW5jZSBQZXJz
b25hbCBDQSAzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsKfSY+QH
o9cT5EtRldy7wXXphZpFEf/50swaHarFN3b9gQkQ99K+ILeaEbGLcqgxhdp5yLcV
dUpMFaA8RXkcziB2DWLwUR2ohrwkIxF8z0U6HDklX1qZqv8wC/0DhKqSaIHjPtCA
RoiXABDSbIZe1HH42GwZzeakrZO+H+dlVhX/2ohezFSZ7FK96K4kL12Ds7PDfzV8
skMopmrQW7piVQjbMxdV/lxwhnzzb8ZTRVvZLb+2sytG2pop3y3LIermwnSDWXPj
aH9pVN/OzQg4IKIdyrGFXGU0roYe6qejI8ROVajmaHdYaV18wzpIyvgwDAue4mV7
LJ3KduHmjdPFZQIDAQABo4IBpjCCAaIwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNV
HQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8v
b2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRp
Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6
MHgwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
ZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9E
aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCow
KAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0O
BBYEFIyfES7m43oEpR5Vi0YIBKbtl3CmMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
i6enIZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQCORxFfdTnp/FhxQqCZHrtgL/m/
5Fk1dqh/2DSNV7G6LtoRyoYeCMjZBTsQP01IritqkJ0OYQEtEyK7PUidSnvg413f
3EwYsO5QmEluYZM4oBVfokor54p6SLWn1qmAUlsSE5dShwUvWAbJIRKjuRi5YgzD
4gII6lAUPx9amTJWTUCLhbtFGhVELmVKSRa+PtM6cz8bAYllNprgKBiLcG2j+eRG
LITO/r/yfsepCIQCbeQ54PHzpjr0fRelcNvxNBGeqEPINX3YcDNdNUtTiOidbVIp
da+xEv7LzalVlW+2JFBAXD6PKaXx50yP7sbJ9rbJbFnn7DhicTWFFEjAG/RK
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIE4DCCA8igAwIBAgIQC1w0NWdbJGfA1zI3+Q1flDANBgkqhkiG9w0BAQsFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTE0MTExODEyMDAwMFoXDTI0MTExODEyMDAwMFowczEL
MAkGA1UEBhMCTkwxFjAUBgNVBAgTDU5vb3JkLUhvbGxhbmQxEjAQBgNVBAcTCUFt
c3RlcmRhbTEPMA0GA1UEChMGVEVSRU5BMScwJQYDVQQDEx5URVJFTkEgU1NMIEhp
Z2ggQXNzdXJhbmNlIENBIDMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQChNsmK4gfxr6c9j2OMBRo3gOA7z5keoaPHiX4rUX+1fF1Brmvf7Uo83sRiXRYQ
RJrD79hzJrulDtdihxgS5HgvIQHqGrp3NRRDUlq/4bItLTp9QCHzLhRQSrSYaFkI
zztYezwb3ABzNiVciqQFk7WR9ebh9ZaCxaXfebcg7LodgQQ4XDvkW2Aknkb1J8NV
nlbKen6PLlNSL4+MLV+uF1e87aTgOxbM9sxZ1/1LRqrOu28z9WA8qUZn2Av+hcP2
TQIBoMPMQ8dT+6Yx/0Y+2J702OU//dS0pi8gMe7FtYVcZrlcSy/C40I7EFYHEjTm
zH4EGvG6t9wZua2atFKvP/7HAgMBAAGjggF1MIIBcTASBgNVHRMBAf8ECDAGAQH/
AgEAMA4GA1UdDwEB/wQEAwIBhjB/BggrBgEFBQcBAQRzMHEwJAYIKwYBBQUHMAGG
GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBJBggrBgEFBQcwAoY9aHR0cDovL2Nh
Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENB
LmNydDBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsNC5kaWdpY2VydC5jb20v
RGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3JsMD0GA1UdIAQ2MDQwMgYE
VR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BT
MB0GA1UdDgQWBBTCuIXX4bkTvdFIvP1e3H2QQnqKqTAfBgNVHSMEGDAWgBSxPsNp
A/i/RwHUmCYaCALvY2QrwzANBgkqhkiG9w0BAQsFAAOCAQEAsCq7NTey6NjZHqT4
kjZBNU3sItnD+RYAMWx4ZyaELcy7XhndQzX88TYSCYxl/YWB6lCjxx0dL3wTZUbX
r+WRDzz5xX+98kdYrwNCT7fmT4eenv6cCS1sC9hc4sIl5dkb1pguY3ViV5D8/yEB
hadOpw3TwI8xkqe2j/H5fp4Oaf9cFdpf9C85mQgZJwsvtvmmDTQTPcGPRFTgdGtY
2xbWxDah6HjKpX6iI4BTBQhhpX6TJl6/GEaYK07s2Kr8BFPhrgmep9vrepWv61x7
dnnqz5SeAs6cbSm551qG7Dj8+6f/8e33oqLC5Ldnbt0Ou6PjtZ4O02dN9cnicemR
1B0/YQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEUDCCAzigAwIBAgIQBSwZ1RU5TGjxj2D3LJepbTANBgkqhkiG9w0BAQwFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQxMjA5MTIwMDAwWhcNMjQxMjA5MTIwMDAwWjBnMQswCQYDVQQG
EwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFt
MQ8wDQYDVQQKEwZURVJFTkExGzAZBgNVBAMTElRFUkVOQSBTU0wgQ0EgMyBHMzB2
MBAGByqGSM49AgEGBSuBBAAiA2IABM+DXfXLPy+htLRKw7qBiZAS/OC/zD0fyF/G
32Rs1Nob2wGhbk7xrbU+kVqueeQIDhYcoC4G8whfKO/qzlgdDiW1p4Ou3aBwCFxZ
+VuF1oSdClDoR/crHPyEMaU6LCAweKOCAaYwggGiMBIGA1UdEwEB/wQIMAYBAf8C
AQAwDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2Fj
ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGB
BgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
cnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2Vy
dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMD0GA1UdIAQ2MDQwMgYE
VR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BT
MB0GA1UdDgQWBBSBmkZUupDOlAwQKgyHMpcsL12AUTAfBgNVHSMEGDAWgBRF66Kv
9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQwFAAOCAQEAGLhet7y0qYQZovyL
41OWDMwVW76cCojYEKDZr/R6jnjnG2kKIkuTz9t2RaybRxmy7Jx2OGFYhM8QaBak
CaW0fBvOEXa8ikQfqZW6RBwYUL5lb+nkcKXJq9AI2QfBlPItwEIrQKHiaAt51Pyh
WLAqcQARGye5WYe8tLuzsMakWPJiRuXiHIfQCtqeyEd1HI0P6Et9RSCk2oAPqrpB
nUDBMmfaS0KyXOOBs6lLQ9BUqMFggR+Nj9XFzx17y+DH3v8+zPinuCMA/D2GwdUw
R2G0j0gJtKkOnyRVrBEFGLpt3oZr7EXh8kexgr4Qie4YwWdshy0u3kN8rj27IMxQ
0pTSbw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIE+zCCA+OgAwIBAgIQCHC8xa8/25Wakctq7u/kZTANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQxMTE4MTIwMDAwWhcNMjQxMTE4MTIwMDAwWjBkMQswCQYDVQQG
EwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFt
MQ8wDQYDVQQKEwZURVJFTkExGDAWBgNVBAMTD1RFUkVOQSBTU0wgQ0EgMzCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMV2Dw/ZQyk7bG3RR63eEL8jwnio
Snc18SNb4EweQefCMQC9iDdFdd25AhCAHo/tZCMERaegOTuBTc9jP8JJ/yKeiLDS
lrlcinQfkioq8hLIt2hUtVhBgUBoBhpPhSn7tU08D08/QJYbzqjMXjX/ZJj1dd10
VAWgNhEEEiRVY++Udy538RV27tOkWUUhn6i+0SftCuirOMo/h9Ha8Y+5Cx9E5+Ct
85XCFk3shKM6ktTPxn3mvcsaQE+zVLHzj28NHuO+SaNW5Ae8jafOHbBbV1bRxBz8
mGXRzUYvkZS/RYVJ+G1ShxwCVgEnFqtyLvRx5GG1IKD6JmlqCvGrn223zyUCAwEA
AaOCAaYwggGiMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMHkG
CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRw
Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3Js
MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
SURSb290Q0EuY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxo
dHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMB0GA1UdDgQWBBRn/YggFCeYxwnS
JRm76VERY3VQYjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkq
hkiG9w0BAQsFAAOCAQEAqSg1esR71tonHqyYzyc2TxEydHTmQN0dzfJodzWvs4xd
xgS/FfQjZ4u5b5cE60adws3J0aSugS7JurHogNAcyTnBVnZZbJx946nw09E02DxJ
WYsamM6/xvLYMDX/6W9doK867mZTrqqMaci+mqege9iCSzMTyAfzd9fzZM2eY/lC
J1OuEDOJcjcV8b73HjWizsMt8tey5gvHacDlH198aZt+ziYaM0TDuncFO7pdP0GJ
+hY77gRuW6xWS++McPJKe1e9GW6LNgdUJi2GCZQfXzer8CM/jyxflp5HcahE3qm5
hS+1NGClXwmgmkMd1L8tRNaN2v11y18WoA5hwnA9Ng==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEVTCCAz2gAwIBAgIQBb0Svc6eVBNFVEdhXnpE8TANBgkqhkiG9w0BAQwFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQxMjA5MTIwMDAwWhcNMjQxMjA5MTIwMDAwWjBsMQswCQYDVQQG
EwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFt
MQ8wDQYDVQQKEwZURVJFTkExIDAeBgNVBAMTF1RFUkVOQSBQZXJzb25hbCBDQSAz
IEczMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzcakjuASx7wxHOCEhau8lMCrZGrD
1g7ZkO9zWJT9gXOm+JOYF9fMHuQ9WE3PoY0OIx8Vao/GSj6kRL6Q4gs7XznebvMK
VNjCR6f2Pb8GFk52O5Xhe5+wCE/H/+jYZwnWo4IBpjCCAaIwEgYDVR0TAQH/BAgw
BgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUF
BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6
Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
cnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmw0LmRp
Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwPQYDVR0gBDYw
NDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNv
bS9DUFMwHQYDVR0OBBYEFCTrTNHO8STGBadlg/JF1vmUqxmLMB8GA1UdIwQYMBaA
FEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBDAUAA4IBAQBK3HL5cB2+
T96Nzu0mFi/5lhe+CQmgKtHCWjJCpPYCpJoDKgjmFQG9jl12AIGlbpUHhV2mi5WQ
7Wem0cNk/VDXVwagD7LdhDFWJ+vUvTOAk5V1D++3b+ZeKCs3Ao6sUzHcYfAaGJO0
WKmTeosqbg9P6/N99Og+mX0f0e/RneOXfsu3QeDy4noQfHlWfFxG48iNGomz0TBD
zde3en0kSGXvB86uvj1q/s+cEbSYDFIa+8ZXctODjwNMHoJvfUXTrmpduIwRRCmb
w8F+T7hlTf0nIvlenysxf/tibqpXVY6kYEjQBspsNOw1qos1YUyjTNWn1ijLQxQs
iinM6lkK2ANU
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFADCCA+igAwIBAgIQA0vuFx+34QY3L9RyQkC9KjANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQxMTE4MTIwMDAwWhcNMjQxMTE4MTIwMDAwWjBpMQswCQYDVQQG
EwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFt
MQ8wDQYDVQQKEwZURVJFTkExHTAbBgNVBAMTFFRFUkVOQSBQZXJzb25hbCBDQSAz
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxqW7H1WC9KU0chRyZZtf
1eqgaNibgolPU2Kce4zODtrUMg6vG4zLpuvb4OsDNJTBh35TIKge+RsXin0BZhJX
aF4tnC4rIahVL1NnCXjN0mkbC5NgbLgoE84fTbGIJq1F+tChzqu3mClWcWzxViRd
pzDgbjFzbtqgV0xki3i1x5zbxt6+0y8xoNaAObXgMUBOhKPMkkniF2z+8GQe+rq8
JYedTyG6yWY5A43UFRC4ezpUz9Vjuk/x3+gbBH3hXKaGtXvjFv5cNFXrUzzx0NeR
2CmD9lmKIR8cw4gvkFMBO1GVQZafXFyKcB7g80om3OURt89J/49kkAsdA5ORTAFB
KwIDAQABo4IBpjCCAaIwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaG
NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
QS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
c3VyZWRJRFJvb3RDQS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUH
AgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFPAh6Ul3
c5+Frhg76FJwFAbtQu7KMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgP
MA0GCSqGSIb3DQEBCwUAA4IBAQA6whsr/mPeu2G0uUeo/HwFsSYgIlGbyD359cVY
HrBeo7KcAkGPMRp/zBtOHfiYfeyPCP138dvSRBBatq0JsOD8YjvUYg2e8aA8TXeK
60Q0e467TikD/CfqPmodL0jj+toZw/8z0uzUTLSMlUthtu+ygC+XyEetp4K/fOH5
iYIQ79G7IxgJnrtxD9MYVLAyU+tSKABqCgZ8QTwHoN1l7HUpuBp+27cr2pHshbWH
m69ipjgUmtvD0ahkg7q+emmYSaDNnjM3Oqa5rxsMLQM0bHObdjrCkbh1lejt2pz9
itu4xmUdm4tVV9TUFLyG6VTU7sI5vl3GbbGvwACRfShpBLHg
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEbjCCA1agAwIBAgIQDQi5YIZPGSJEUhoAbXmU4DANBgkqhkiG9w0BAQwFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQxMjA5MTIwMDAwWhcNMjQxMjA5MTIwMDAwWjBwMQswCQYDVQQG
EwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFt
MQ8wDQYDVQQKEwZURVJFTkExJDAiBgNVBAMTG1RFUkVOQSBDb2RlIFNpZ25pbmcg
Q0EgMyBHMzB2MBAGByqGSM49AgEGBSuBBAAiA2IABOJhkgGcp6H4i5PUlmg3DRD6
NiX+Vx+H3ftyebx3+DnI6Mv68qIqxdmi54tumL1+qgVhe9lfk2UjMvhMcAtnf9YL
J0+ZlT4/EG2bsWSQwYnJIC1K0NUq7146JFkmGSVNFKOCAbswggG3MBIGA1UdEwEB
/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMD
MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRo
dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
Y3JsMDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
cmVkSURSb290Q0EuY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMB0GA1UdDgQWBBTygS5D7R0k
1PDRRjwBNv3no4AB/DAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAN
BgkqhkiG9w0BAQwFAAOCAQEAejAjhvCUEl+VAQ/N25e5t72WBNPbnoZOaKG/7r37
MAfoYVXpPx+Yy1gpZjtUOXbRpb1zOTMY36eutGm+qUv0sbYpQAIzFu4DSlCe2AJY
8eNeT1IOAt3hZKA+aZNGI+E+7c0DqkLbI/YbAh02YVv1kX1yxpiYHtmCADOztgH6
VNF4UTjSm977UUrjf1w0GMTBTjkVmimlla6iq3LqXOhKMgip8c2FdDeBM/Vb0i51
q3J9r38p2qKQKHYsucO2OEQClBq+7A89EI5F4HyaJvlaS4GTs/x784EMRR9EfxzB
DkrhCx1wpP0e7lnLyutHYIXDezK0DbjmXfUHFjQwYWsZyQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFGTCCBAGgAwIBAgIQDbnGEbOq/3RgewIGXryqxTANBgkqhkiG9w0BAQsFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMTQxMTE4MTIwMDAwWhcNMjQxMTE4MTIwMDAwWjBtMQswCQYDVQQG
EwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFt
MQ8wDQYDVQQKEwZURVJFTkExITAfBgNVBAMTGFRFUkVOQSBDb2RlIFNpZ25pbmcg
Q0EgMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKri5yAvrBCV+s0k
5fig3/WirZ+8s8nh+B/EPuSWQW275wPwDBRxvaY4UbdQOac59kJt4lzEnv+reNW9
ZwMh6W4EzEbfxYcklJ/91iwFYYOTsvXhd2QqutVQ87bab9CLvH8+awDuXLM0v1DA
+MjwfVd+dApIr21ITItvil4jvnbLXYR4VjuIZ5vRiGCiCEQHiImmw/LcKuBzbMKb
hCb3FD6LSqhpCPSTiegfaeu0KnUyCxmPfLMMuFrkRrRka8fQUJvwgLRPNXGfIH9Z
yFRm7M0zE98JMoUQAmFoPLSSJGC6oNK8tccHvfxQ6jRgCB8CoY8ftyz9WqZJgLk5
+llJ+RkCAwEAAaOCAbswggG3MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/
BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHkGCCsGAQUFBwEBBG0wazAkBggr
BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdo
dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290
Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5j
b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3Js
NC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMD0GA1Ud
IAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2Vy
dC5jb20vQ1BTMB0GA1UdDgQWBBQyCsEMwWg+V6gt+Xki5Y6c6USOMjAfBgNVHSME
GDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQsFAAOCAQEARK1Q
ChmvA+HzpJ7KM8s0RJW06t34uUi15WqZw7cBjq7VxHMefVoI/Rm/IEzFAbvIstsQ
ydkrDd3OcTzcW665Z0vvvbBEmLhhKdyoenOyFL10PzBcw3nADPRW3LP+4Yl4RaWH
6Fkoj0SLbQY/sTbEMO50bFTLxAPXb3ga42xDdhVGniJJWZdNON4bTNJ8lhv8utfp
ehgwFyzVhoku0JoZPjXyxiu+UUlnSR1lIa9CIk4NTQ8aAumbgnbn/Iqwe3VWTeo/
kA+KJwRVMBN6U6H+9l6i9kk5VF8DyYtqNc4wqALgQBXtFZUQHQZj7++No5rhwVpg
mjGEl7nwi5AqasvHIg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIBADANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEh
MB8GA1UEChMYVGhlIEdvIERhZGR5IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBE
YWRkeSBDbGFzcyAyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA0MDYyOTE3
MDYyMFoXDTM0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRo
ZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3Mg
MiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN
ADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XCA
PVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux6w
wdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLOtXi
EqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWoriMY
avx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZEewo+
YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjgcAwgb0wHQYDVR0OBBYEFNLE
sNKR1EwRcbNhyz2h/t2oatTjMIGNBgNVHSMEgYUwgYKAFNLEsNKR1EwRcbNhyz2h
/t2oatTjoWekZTBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYVGhlIEdvIERhZGR5
IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
ggEBADJL87LKPpH8EsahB4yOd6AzBhRckB4Y9wimPQoZ+YeAEW5p5JYXMP80kWNy
OO7MHAGjHZQopDH2esRU1/blMVgDoszOYtuURXO1v0XJJLXVggKtI3lpjbi2Tc7P
TMozI+gciKqdi0FuFskg5YmezTvacPd+mSYgFFQlq25zheabIZ0KbIIOqPjCDPoQ
HmyW74cNxA9hi63ugyuV+I6ShHI56yDqg+2DzZduCLzrTia2cyvk0/ZM/iZx4mER
dEr/VxqHD3VILs9RaRegAhJhldXRQLIQTO7ErBBDpqWeCtWVYpoNz4iCxTIM5Cuf
ReYNnyicsbkqWletNw+vHX/bvZ8=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFiTCCA3GgAwIBAgIQD1JcWfqttreDvYLeCQ5b/zANBgkqhkiG9w0BAQsFADBQ
MQswCQYDVQQGEwJVUzEYMBYGA1UEChMPV0ZBIEhvdHNwb3QgMi4wMScwJQYDVQQD
Ex5Ib3RzcG90IDIuMCBUcnVzdCBSb290IENBIC0gMDMwHhcNMTMxMjA5MTIwMDAw
WhcNMjMxMjA5MTIwMDAwWjBPMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNl
cnQxLTArBgNVBAMTJERpZ2lDZXJ0IEhvdHNwb3QgMi4wIEludGVybWVkaWF0ZSBD
QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKuoXpFSupZIWNENKaio
SdMoTdqtDTjK44HPnMthnpgTy/YECra8/zRnungwQZPayfFrDM3A8wVkO8JawUau
vPO4NglNTXzO0kvAiPj02DRkdipFCXEYbUOzF+iW6KsQOxSQBrOFgb8GAMv77xYM
riYMKeNDDaJZJd4XkiwLhP+vDbc9nd5OiqDbmaYUyv5Fm9Eg1rBLhBxYiCSLieDW
ts3XZwGRrKskXWv+ipJZEBXgPvBIVzzDF365tFWUje6iXMdmr2xEoOVN8pUHHnZX
J3SKffCKFGEgoagVLFxClxufXL+LmujWZXgN1EiYtb1thP2qtIc/mUAk2FPQQqAS
yv0CAwEAAaOCAV4wggFaMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD
AgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
aWNlcnQuY29tMH8GA1UdHwR4MHYwOaA3oDWGM2h0dHA6Ly9jcmw0LmRpZ2ljZXJ0
LmNvbS9Ib3RzcG90MjBUcnVzdFJvb3RDQTAzLmNybDA5oDegNYYzaHR0cDovL2Ny
bDMuZGlnaWNlcnQuY29tL0hvdHNwb3QyMFRydXN0Um9vdENBMDMuY3JsMD0GA1Ud
IAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2Vy
dC5jb20vQ1BTMB0GA1UdDgQWBBQC1E6gGtpyl1PQa860Mg2pqkaykjAfBgNVHSME
GDAWgBRnDkksYRee6+3gVOeE2ZutZGBzZTANBgkqhkiG9w0BAQsFAAOCAgEAmc8y
etvXRCLDW2OgyXH/THw3T1PEONXw0YCvVMa+PXC0W+LCsmhbgilTtu+f1dbTXead
C5wuNp1xt1nndZRoo8Og0et1CEZU7yUN3rtG11fltT+6sldVzKy4JOzxFMEOgxCT
B323DpWzZybobJ4Vsgo7WVwjaX0nuf7T08NYD31u6eb6+gdtABky/NO0uI6skNC8
IZiYcAWvVAbKrYBGnrCidGXAHw61xvCipeO8p4V/JK/0HkcLlB4siCbhbox7p3hZ
d3ud7dbHrWDEQsilQTaeYUDKvOtHD0mCzDwPyr9zh1yUnst6GFr5OR3XRk/+l6/x
biBiqKMYKICoGMxEU6QTiNOQMuqurgmv8aJqLUn6Abso8XHxFnZ/i1ggkD/zCVdw
nftXfoFXFeP8Rko5uPefE3uqIx7QYujZktZVpr1bfxuaaN6MXGppKJq0PBDo16Di
W7AmztzkEDVtoYaVIdln1v9uL05lnOD/AW3Z/PMajsT3E052q9Fdr5xDrQKMY+Mn
XcXxVlgcV8NKnn5OaWGfqjAGJOpvWQ0sS55IkvKNRNEEDyjwAZgBnGtKgQ9YM90A
5UJtFyuypV8ifJ+qZ61nTDSvU7FHqVmJbYeJGjwzYOjsllPP3Gr8VdkN+dljEHpQ
ZsWEJbXVlq3GPwHXMx+xoMODHgKmuFGUSjK9juY=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFbDCCA1SgAwIBAgIQDLMPcPKGpDPguQmJ3gHttzANBgkqhkiG9w0BAQsFADBQ
MQswCQYDVQQGEwJVUzEYMBYGA1UEChMPV0ZBIEhvdHNwb3QgMi4wMScwJQYDVQQD
Ex5Ib3RzcG90IDIuMCBUcnVzdCBSb290IENBIC0gMDMwHhcNMTMxMjA4MTIwMDAw
WhcNNDMxMjA4MTIwMDAwWjBQMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPV0ZBIEhv
dHNwb3QgMi4wMScwJQYDVQQDEx5Ib3RzcG90IDIuMCBUcnVzdCBSb290IENBIC0g
MDMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCsdEtReIUbMlO+hR6b
yQk4nGVITv3meYTaDeVwZnQVal8EjHuu4Kd89g8yRYVTv3J1kq9ukE7CDrDehrXK
ym+8VlR7ro0lB/lwRyNk3W7yNccg3AknQ0x5fKVwcFznwD/FYg37owGmhGFtpMTB
cxzreQaLXvLta8YNlJU10ZkfputBpzi9bLPWsLOkIrQw7KH1Wc+Oiy4hUMUbTlSi
cjqacKPR188mVIoxxUoICHyVV1KvMmYZrVdc/b5dbmd0haMHxC0VSqbydXxxS7vv
/lCrC2d5qbKE66PiuBPkhzyU7SI9C8GU/S7akYm1MMSTn5W7lSp2AWRDnf9LQg51
dLvDxJ7t2fruXtSkkqG/cwY1yQI8O+WZYPDThKPcDmNbaxVE9lOizAHXFVsfYrXA
PbbMOkzKehYwaIikmNgcpxtQNw+wikJiZb9N8VwwtwHK71XEFi+n5DGlPa9VDYgB
YkBcxvVo2rbE3i3teQgHm+pWZNP08aFNWwMk9yQkm/SOGdLq1jLbQA9yd7fyR1Ct
W1GLzKi1Ojr/6XiB9/noL3oxP/+gb8OSgcqVfkZp4QLvrGdlKiOI2fE7Bslmzn6l
B3UTpApjab7BQ99rCXzDwt3Xd7IrCtAJNkxi302J7k6hnGlW8S4oPQBElkOtoH9y
XEhp9rNS0lZiuwtFmWW2q50fkQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4G
A1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUZw5JLGEXnuvt4FTnhNmbrWRgc2UwDQYJ
KoZIhvcNAQELBQADggIBAFPoGFDyzFg9B9+jJUPGW32omftBhChVcgjllI07RCie
KTMBi47+auuLgiMox3xRyP7/dX7YaUeMXEQ1BMv6nlrsXWv1lH4yu+RNuehPlqRs
fY351mAfPtQ654SBUi0Wg++9iyTOfgF5a9IWEDt4lnSZMvA4vlw8pUCz6zpKXHnA
RXKrpY3bU+2dnrFDKR0XQhmAQdo7UvdsT1elVoFIxHhLpwfzx+kpEhtrXw3nGgt+
M4jNp684XoWpxVGaQ4Vvv00Sm2DQ8jq2sf9F+kRWszZpQOTiMGKZr0lX2CI5cww1
dfmd1BkAjI9cIWLkD8YSeaggZzvYe1o9d7e7lKfdJmjDlSQ0uBiG77keUK4tF2fi
xFTxibtPux56p3GYQ2GdRsBaKjH3A3HMJSKXwIGR+wb1sgz/bBdlyJSylG8hYD//
0Hyo+UrMUszAdszoPhMY+4Ol3QE3QRWzXi+W/NtKeYD2K8xUzjZM10wMdxCfoFOa
8bzzWnxZQlnu880ULUSHIxDPeE+DDZYYOaN1hV2Rh/hrFKvvV+gJj2eXHF5G7y9u
Yg7nHYCCf7Hy8UTIXDtAAeDCQNon1ReN8G+XOqhLQ9TalmnJ5U5ARtC0MdQDht7T
DZpWeEVv+pQHARX9GDV/T85MV2RPJWKqfZ6kK0gvQDkunADdg8IhZAjwMMx3k6B/
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIHOjCCBSKgAwIBAgIQDxJY+3h8tRbKrTypxPAK9DANBgkqhkiG9w0BAQsFADBQ
MQswCQYDVQQGEwJVUzEYMBYGA1UEChMPV0ZBIEhvdHNwb3QgMi4wMScwJQYDVQQD
Ex5Ib3RzcG90IDIuMCBUcnVzdCBSb290IENBIC0gMDMwHhcNMTMxMjA5MTIwMDAw
WhcNMjMxMjA5MTIwMDAwWjBQMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOV2ktRmkg
QWxsaWFuY2UxKDAmBgNVBAMTH1dGQSBIb3RzcG90IDIuMCBJbnRlcm1lZGlhdGUg
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAq0kuw5iFUG37g6ak
G9DIs7+Qfc/21OcTekJ4v3VDmlAeOFIDdyaMziJx4ecwRP09g3dkum5dNsWGH0Ef
SkOswPhisfBYIdNdMFbCayBtWLxmC5QPCzb+UzcLpeCqkv2R14dbo9pGt8R+//Uk
LKGxTopC3Hg7+E6+Ndv67HUa8hobYTMRmhTvIm5G+uP0JUjXNMGs35na/XvAVh8c
7rbNSMM1Gdjw0UzWA4RuYD01GqNfHnxmOG855RP+JIMykGlkTHClEw5x2QInvrt4
3U06V94zrBNusdmEzR6/AIXhcH1vjvtm9jS94tblXTTG/gmk49TCNTqvUkDtbvOB
ZrMHAgMBAAGjggMOMIIDCjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQE
AwIBhjA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
Z2ljZXJ0LmNvbTB/BgNVHR8EeDB2MDmgN6A1hjNodHRwOi8vY3JsNC5kaWdpY2Vy
dC5jb20vSG90c3BvdDIwVHJ1c3RSb290Q0EwMy5jcmwwOaA3oDWGM2h0dHA6Ly9j
cmwzLmRpZ2ljZXJ0LmNvbS9Ib3RzcG90MjBUcnVzdFJvb3RDQTAzLmNybDA9BgNV
HSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNl
cnQuY29tL0NQUzBoBgNVHREBAf8EXjBcoCcGCysGAQQBgr5oAQEBoBgEFmVuZ1NQ
IE9yYW5nZSBUZXN0IE9ubHmgMQYLKwYBBAGCvmgBAQGgIgQga29yU1Ag7Jik66CM
7KeAIO2FjOyKpO2KuCDsoITsmqkwggFCBggrBgEFBQcBDASCATQwggEwoIIBLDCC
ASiggZEwgY4wgYswdxYJaW1hZ2UvcG5nMDMwMTANBglghkgBZQMEAgEFAAQgz6p0
qK2vhYIGyPW1v+5Fcoru6r1Hq1DTYgySwVPDTGswNRYzaHR0cDovL3d3dy5yMi10
ZXN0YmVkLndpLWZpLm9yZy9pY29uX29yYW5nZV96eHgucG5nMBACAhBYAgIAgAIB
PYQDenh4oIGRMIGOMIGLMHcWCWltYWdlL3BuZzAzMDEwDQYJYIZIAWUDBAIBBQAE
IMs1XLp6IVnfjgrh2J+kgZ5Bj69YDAjWKH9mIpgTV5WNMDUWM2h0dHA6Ly93d3cu
cjItdGVzdGJlZC53aS1maS5vcmcvaWNvbl9vcmFuZ2VfZW5nLnBuZzAQAgItcwIC
AKACAUyEA2VuZzAdBgNVHQ4EFgQUG0XTFF8x8ywUPai50NQph2fIfJcwHwYDVR0j
BBgwFoAUZw5JLGEXnuvt4FTnhNmbrWRgc2UwDQYJKoZIhvcNAQELBQADggIBAC2w
M/vVrzJFuRhcZmVr//uKZqirB408vm1iaEZgNg5OH6DdFVgF+VKmXVOCHJFrGyMc
CqU6Js3KMbLa8HHPDEk/4JYE+pBK0uFfM6Y16zu3vmmZlT3J/yL8DqZuS0Tt+fLH
xm7VcZXT4KbWSqR2hrsgwBVcbpo1EY4tD/mOv5fiFQpJJtIbsWRzkc2oGC404/1w
3Ew5ELAQmSwjQ/bi31xK5Du2N+FIS//cBw7ULcKhXTY8ijJnFU12EYIfBCFL/yEM
NaLRwXj+wa+wamSbPtzsSNBBbg+rP/4AFjSAhRg5LTWZb1aYwiEIAA4bgTBVr4Pi
bhhbojvBu8AVYPv48k0W/IoEtyN1nWVkgcKM5qTnxAPROzLuzIeThkftqdFfJAAJ
Iu6B6/mhm714k+J5CLIst9o6coxoBVTcYoXmJPsz01wDJJcVkTQzU3QrWgdYnH8c
SID3mRLklLm7T6CZZq/n2tU0gUjceyJjxRvqwaz3dZQHL//cCIeOotQYVBrFDZt+
e6nN8Tx/k2he4Dc/OJMCpajxm1xxZnUbi6tBJzpniYhHZsLghktgndr1t/IdsCJV
p6xdUJkHrE13lVGxQVDThnJwTTeVmsmiRTRY3RYYaywwWz35S7Bf6iXPp3CsZJvS
HsN9BemxsR2FL/RrU2g9zBz0Gj04ngTB7+b+/i4v
-----END CERTIFICATE-----

-----END CERTIFICATES LIST-----

*/

#ifdef __cplusplus
} // extern "C"
#endif
