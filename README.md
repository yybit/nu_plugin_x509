[![crates.io](https://img.shields.io/crates/v/nu_plugin_x509.svg)](https://crates.io/crates/nu_plugin_x509)
[![docs.rs](https://docs.rs/nu_plugin_x509/badge.svg)](https://docs.rs/nu_plugin_x509)

# nu_plugin_x509

`nu_plugin_x509` is a Nushell plugin for parsing and generating x509 certificates.

## Installation

```shell
cargo install nu_plugin_x509
plugin add ~/.cargo/bin/nu_plugin_x509
plugin use x509
```

## Usage

```shell
# generate self signed crt with subject alternative names
['localhost' '10.1.1.1'] | to x509
# generate self signed crt with other parameters
['localhost' '10.10.10.10'] | to x509 -n hello -b 2021-01-01 -e 2055-01-01 -u digital_signature,key_agreement -c 2
# parse
open xxx.pem | from x509 | first
# generate and parse
['localhost'] | to x509 | get crt | from x509 | first
```

## `to x509` Command Parameters
- `-n`: Specifies the common name (CN) for the certificate.
- `-b`: Specifies the beginning date for the certificate validity period in `YYYY-MM-DD` format. Default is `1975-01-01`.
- `-e`: Specifies the end date for the certificate validity period in `YYYY-MM-DD` format. Default is `4096-01-01`.
- `-c`: Specifies the CA constraint (0 for unconstrained, positive integer for constrained). If not specified, the certificate is not a CA certificate.
- `-u`: Specifies the usage of the certificate, options include (use commas to separate multiple options):
    - `digital_signature`
    - `content_commitment`
    - `key_encipherment`
    - `data_encipherment`
    - `key_agreement`
    - `key_cert_sign`
    - `crl_sign`
    - `encipher_only`
    - `decipher_only`

## Example

### Generate x509 Certificate

```shell
~> ['localhost' '10.1.1.1'] | to x509 -n hello -b 2021-01-01 -e 2055-01-01 
╭─────┬──────────────────────────────────────────────────────────────────╮
│ crt │ -----BEGIN CERTIFICATE-----                                      │
│     │ MIIBQjCB6KADAgECAhRCHhToL8o1wPj27wizZY82Co7s4DAKBggqhkjOPQQDAjAQ │
│     │ MQ4wDAYDVQQDDAVoZWxsbzAgFw0yMTAxMDEwMDAwMDBaGA8yMDU1MDEwMTAwMDAw │
│     │ MFowEDEOMAwGA1UEAwwFaGVsbG8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQb │
│     │ O8WoMFm8p9zN1BfaVRyZ5eshzsYRqaHMt/8vvfPJUdW+Bb0hJ/AaqXvega/Ztmnm │
│     │ 1/YVxZIbPhjnCf1hF3cRox4wHDAaBgNVHREEEzARgglsb2NhbGhvc3SHBAoBAQEw │
│     │ CgYIKoZIzj0EAwIDSQAwRgIhAK2NtYaYmzyJFXTYQrBTSRtZQfU+ctJL7+PJptuF │
│     │ 0RI3AiEAon+24PgK5tkpyTfod2y8Y8Tig88SB7KBAhiikM9atGQ=             │
│     │ -----END CERTIFICATE-----                                        │
│     │                                                                  │
│ key │ -----BEGIN PRIVATE KEY-----                                      │
│     │ MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6lkbxzSXNQqEkLIm │
│     │ LsZoAKLDMH/iGdKatzhmc/0qVkWhRANCAAQbO8WoMFm8p9zN1BfaVRyZ5eshzsYR │
│     │ qaHMt/8vvfPJUdW+Bb0hJ/AaqXvega/Ztmnm1/YVxZIbPhjnCf1hF3cR         │
│     │ -----END PRIVATE KEY-----                                        │
│     │                                                                  │
╰─────┴──────────────────────────────────────────────────────────────────╯
```

### Parse x509 Certificate

```shell
~> open /etc/ssl/certs/AffirmTrust_Commercial.pem | from x509 | first
╭─────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ version             │ 2                                                                                                                 │
│ serial              │ 7777062726a9b17c                                                                                                  │
│ issuer              │ C=US, O=AffirmTrust, CN=AffirmTrust Commercial                                                                    │
│                     │ ╭────────────┬──────────────╮                                                                                     │
│ validity            │ │ not_before │ 14 years ago │                                                                                     │
│                     │ │ not_after  │ in 6 years   │                                                                                     │
│                     │ ╰────────────┴──────────────╯                                                                                     │
│ subject             │ C=US, O=AffirmTrust, CN=AffirmTrust Commercial                                                                    │
│                     │ ╭──────────────────────────┬─────────────────────────────────────────────────╮                                    │
│ subject_pki         │ │ subject_public_key       │ rsaEncryption                                   │                                    │
│                     │ │ subject_public_key_value │ 30:82:01:0a:02:82:01:01:00:f6:1b:4f:67:07:2b:a1 │                                    │
│                     │ │                          │ 15:f5:06:22:cb:1f:01:b2:e3:73:45:06:44:49:2c:bb │                                    │
│                     │ │                          │ 49:25:14:d6:ce:c3:b7:ab:2c:4f:c6:41:32:94:57:fa │                                    │
│                     │ │                          │ 12:a7:5b:0e:e2:8f:1f:1e:86:19:a7:aa:b5:2d:b9:5f │                                    │
│                     │ │                          │ 0d:8a:c2:af:85:35:79:32:2d:bb:1c:62:37:f2:b1:5b │                                    │
│                     │ │                          │ 4a:3d:ca:cd:71:5f:e9:42:be:94:e8:c8:de:f9:22:48 │                                    │
│                     │ │                          │ 64:c6:e5:ab:c6:2b:6d:ad:05:f0:fa:d5:0b:cf:9a:e5 │                                    │
│                     │ │                          │ f0:50:a4:8b:3b:47:a5:23:5b:7a:7a:f8:33:3f:b8:ef │                                    │
│                     │ │                          │ 99:97:e3:20:c1:d6:28:89:cf:94:fb:b9:45:ed:e3:40 │                                    │
│                     │ │                          │ 17:11:d4:74:f0:0b:31:e2:2b:26:6a:9b:4c:57:ae:ac │                                    │
│                     │ │                          │ 20:3e:ba:45:7a:05:f3:bd:9b:69:15:ae:7d:4e:20:63 │                                    │
│                     │ │                          │ c4:35:76:3a:07:02:c9:37:fd:c7:47:ee:e8:f1:76:1d │                                    │
│                     │ │                          │ 73:15:f2:97:a4:b5:c8:7a:79:d9:42:aa:2b:7f:5c:fe │                                    │
│                     │ │                          │ ce:26:4f:a3:66:81:35:af:44:ba:54:1e:1c:30:32:65 │                                    │
│                     │ │                          │ 9d:e6:3c:93:5e:50:4e:7a:e3:3a:d4:6e:cc:1a:fb:f9 │                                    │
│                     │ │                          │ d2:37:ae:24:2a:ab:57:03:22:28:0d:49:75:7f:b7:28 │                                    │
│                     │ │                          │ da:75:bf:8e:e3:dc:0e:79:31:02:03:01:00:01       │                                    │
│                     │ ╰──────────────────────────┴─────────────────────────────────────────────────╯                                    │
│                     │ ╭───┬───────────┬──────────────────────┬──────────┬─────────────────────────────────────────────────────────────╮ │
│ extensions          │ │ # │    oid    │         name         │ critical │                            value                            │ │
│                     │ ├───┼───────────┼──────────────────────┼──────────┼─────────────────────────────────────────────────────────────┤ │
│                     │ │ 0 │ 2.5.29.14 │ SubjectKeyIdentifier │ false    │ 9d:93:c6:53:8b:5e:ca:af:3f:9f:1e:0f:e5:99:95:bc:24:f6:94:8f │ │
│                     │ │ 1 │ 2.5.29.19 │ BasicConstraints     │ true     │ ╭─────────────────────┬──────╮                              │ │
│                     │ │   │           │                      │          │ │ ca                  │ true │                              │ │
│                     │ │   │           │                      │          │ │ path_len_constraint │ 0    │                              │ │
│                     │ │   │           │                      │          │ ╰─────────────────────┴──────╯                              │ │
│                     │ │ 2 │ 2.5.29.15 │ KeyUsage             │ true     │ ╭───────────────────┬───────╮                               │ │
│                     │ │   │           │                      │          │ │ digital_signature │ false │                               │ │
│                     │ │   │           │                      │          │ │ non_repudiation   │ false │                               │ │
│                     │ │   │           │                      │          │ │ key_encipherment  │ false │                               │ │
│                     │ │   │           │                      │          │ │ data_encipherment │ false │                               │ │
│                     │ │   │           │                      │          │ │ key_agreement     │ false │                               │ │
│                     │ │   │           │                      │          │ │ key_cert_sign     │ true  │                               │ │
│                     │ │   │           │                      │          │ │ crl_sign          │ true  │                               │ │
│                     │ │   │           │                      │          │ │ encipher_only     │ false │                               │ │
│                     │ │   │           │                      │          │ │ decipher_only     │ false │                               │ │
│                     │ │   │           │                      │          │ ╰───────────────────┴───────╯                               │ │
│                     │ ╰───┴───────────┴──────────────────────┴──────────┴─────────────────────────────────────────────────────────────╯ │
│ signature_algorithm │ sha256WithRSAEncryption                                                                                           │
│ signature_value     │ 58:ac:f4:04:0e:cd:c0:0d:ff:0a:fd:d4:ba:16:5f:29                                                                   │
│                     │ bd:7b:68:99:58:49:d2:b4:1d:37:4d:7f:27:7d:46:06                                                                   │
│                     │ 5d:43:c6:86:2e:3e:73:b2:26:7d:4f:93:a9:b6:c4:2a                                                                   │
│                     │ 9a:ab:21:97:14:b1:de:8c:d3:ab:89:15:d8:6b:24:d4                                                                   │
│                     │ f1:16:ae:d8:a4:5c:d4:7f:51:8e:ed:18:01:b1:93:63                                                                   │
│                     │ bd:bc:f8:61:80:9a:9e:b1:ce:42:70:e2:a9:7d:06:25                                                                   │
│                     │ 7d:27:a1:fe:6f:ec:b3:1e:24:da:e3:4b:55:1a:00:3b                                                                   │
│                     │ 35:b4:3b:d9:d7:5d:30:fd:81:13:89:f2:c2:06:2b:ed                                                                   │
│                     │ 67:c4:8e:c9:43:b2:5c:6b:15:89:02:bc:62:fc:4e:f2                                                                   │
│                     │ b5:33:aa:b2:6f:d3:0a:a2:50:e3:f6:3b:e8:2e:44:c2                                                                   │
│                     │ db:66:38:a9:33:56:48:f1:6d:1b:33:8d:0d:8c:3f:60                                                                   │
│                     │ 37:9d:d3:ca:6d:7e:34:7e:0d:9f:72:76:8b:1b:9f:72                                                                   │
│                     │ fd:52:35:41:45:02:96:2f:1c:b2:9a:73:49:21:b1:49                                                                   │
│                     │ 47:45:47:b4:ef:6a:34:11:c9:4d:9a:cc:59:b7:d6:02                                                                   │
│                     │ 9e:5a:4e:65:b5:94:ae:1b:df:29:b0:16:f1:bf:00:9e                                                                   │
│                     │ 07:3a:17:64:b5:04:b5:23:21:99:0a:95:3b:97:7c:ef                                                                   │
╰─────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```