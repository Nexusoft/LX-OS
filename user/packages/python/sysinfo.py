# System information certificate support code

# Needs to install pyopenssl
from OpenSSL import crypto
from hashlib import sha1
import time

def generate_cert(pkey, sn, statements, extension_prefix):
    cert = crypto.X509()
    cert.set_pubkey(pkey)
    # Version 3 is actually value 2..
    cert.set_version(2)
    tz = `time.timezone/3600`
    if tz[0] == '-':
        tz[0] = '+'
    else:
        tz = '-' + tz
    if len(tz) == 2:
        tz = tz[0] + '0' + tz[1]
    tz = tz + '00'
    ctime = time.strftime("%Y%m%d%H%M%S") + tz
    nyear = int(ctime[:4]) + 1
    print ctime
    print `nyear` + ctime[4:]
    cert.set_notBefore(ctime)
    cert.set_notAfter(`nyear` + ctime[4:])
    cert.set_serial_number(sn)

    issuer = cert.get_issuer()
    issuer.countryName = "US"
    issuer.stateOrProvinceName = "New York"
    issuer.localityName = "Ithaca"
    issuer.organizationName = "Cornell University"
    issuer.organizationalUnitName = "Computer Science Department"
    issuer.commonName = "Nexus Operating System"
    issuer.emailAddress = "nexus@systems.cs.cornell.edu"
    # From Nexus to Nexus ...
    cert.set_subject(issuer)

    # Parse into correct extensions 
    i = 0
    extensions = []
    for s in statements:
        extensions.append(crypto.X509Extension(extension_prefix + "." + `i`, False, "ASN1:UTF8String:" + s))
        i = i + 1
    cert.add_extensions(extensions)

    cert.sign(pkey, "sha1")

    certbuf = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    return certbuf

def gen_sha1(s):
    return "0x" + sha1(s).hexdigest()

def test_main():
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 1024)

    statements = ["sysinfo.app says cpu[0].clockrate = 3.0GHz", 
                  "sysinfo.app says cpu[1].clockrate = 3.0GHz",
                  "sysinfo.app says memory.size = 4.0GB",
                  "kernel says sysinfo.app speaksfor sha1." + gen_sha1("sysinfo.app")]
    digest = gen_sha1("".join(statements))
    statements.append("sysinfo.app says digest = sha1." + digest)

    print generate_cert(pkey, 123456789, statements, "1.2.3.4")


