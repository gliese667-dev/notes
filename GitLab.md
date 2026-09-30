[Gitlab](https://github.com/gliese667-dev/notes/blob/main/GitLab.md) © 2025 by [Ole Martin Håland](https://github.com/gliese667-dev) is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).

-----------------------------------------------------------------------------------------------------------------------
# GitLab

This note is just for me to remember what I found out while doing these things.

## Table of Contents
- [1) Installing and setting up](#1-installing-and-setting-up)
  - [Installing and setting up GitLab with certificates for TLS](#setting-up-gitlab-with-certificates-for-tls)
- [2) Upgrading](#2-upgrading)
- [Appendix A - Acronyms, keywords, terms](#appendix-a---acronyms-keywords-terms)
  - [Extensions & Usage Fields](#extensions--usage-fields)

-----------------------------------------------------------------------------------------------------------------------
### 1) Installing and setting up

I have not actually installed it yet.

#### Setting up GitLab with certificates for [TLS](#appendix-a---acronyms-keywords-terms)

Copy the certificate chain and private key to GitLab’s default SSL folder `/etc/gitlab/ssl`:
```bash
# Create the SSL directory if it does not already exist:
sudo mkdir -p /etc/gitlab/ssl
sudo chmod 755 /etc/gitlab/ssl

# If the leaf key is encrypted, write an unencrypted runtime copy for GitLab:
#sudo openssl pkey -in ~/pki/private/leaf.key -out /etc/gitlab/ssl/gitlab.key

# Otherwise make a copy of the key for GitLab:
sudo cp ~/pki/private/leaf.key /etc/gitlab/ssl/gitlab.key

# Copy the certificate:
sudo cp ~/pki/issued/server-chain.crt /etc/gitlab/ssl/gitlab.crt

# Owner: rw-, Group: ---, Others: ---
sudo chmod 600 /etc/gitlab/ssl/gitlab.key
# Owner: rw-, Group: r--, Others: r--
sudo chmod 644 /etc/gitlab/ssl/gitlab.crt
```

Ensure your ``/etc/gitlab/gitlab.rb`` matches one of the SAN hostnames:
```bash
external_url "https://gitlab"  # or the FQDN you used in SANs

# Use our manually managed certificates instead of the Let's Encrypt integration:
letsencrypt['enable'] = false

# Use the filenames created by the copy commands above, regardless of hostname:
nginx['ssl_certificate']     = "/etc/gitlab/ssl/gitlab.crt"
nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/gitlab.key"
```

Apply and reload NGINX:
```bash
sudo gitlab-ctl reconfigure
sudo gitlab-ctl hup nginx
```

Verify what’s being served:
```bash
openssl s_client -connect gitlab:443 -servername gitlab </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates -ext subjectAltName
```
or with curl:
```bash
curl -vk https://gitlab
```
Issuer should include "Your Company - Intermediate CA" (or the intermediate CA name you configured).
Open SSL SAN should list every DNS.* you added

```bash
# Show the entire served certificate chain (useful for debugging proxies/load balancers)
openssl s_client -connect gitlab:443 -servername gitlab -showcerts </dev/null
```

-----------------------------------------------------------------------------------------------------------------------
### 2) Upgrading

Some useful sources:
- [Upgrade GitLab](https://docs.gitlab.com/update/)
    - [Upgrade a GitLab instance](https://docs.gitlab.com/update/upgrade/)
        - [Upgrade Linux package](https://docs.gitlab.com/update/package/#by-using-the-official-repositories-recommended)
        - [Upgrade Path Tool](https://gitlab-com.gitlab.io/support/toolbox/upgrade-path/) - A tool for finding the necessary versions 
    - [Releases and maintenance](https://docs.gitlab.com/policy/maintenance/)

At a glance:
- Consult the Upgrade Path Tool
    - Enter the version you have and the version you want to end up with
    - A list with all the necessary waypoints will be presented along with special notices for select versions.
    - For each version check that a package for your current linux distro version exist.


### Appendix A - Acronyms, keywords, terms

| Term              | Meaning | Short explanation |
|-------------------|---------|--------------|
| NGINX             | [nginx](https://en.wikipedia.org/wiki/Nginx) | High-performance HTTP/TLS reverse proxy bundled with GitLab. |
| TLS               | [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security) | A cryptographic protocol designed to provide communications security over a computer network, such as the Internet. |

##### Extensions & Usage Fields
| Abbreviation | Keyword                  | Meaning |
|--------------|--------------------------|---------|
|              | `CA:true` / `CA:false`   | Marks whether the cert may act as a Certificate Authority. |
|              | `pathlen`                | Max number of subordinate CA levels allowed below this CA (does not restrict end-entities). |
| KU           | `keyUsage`               | Specifies key purposes: `digitalSignature`, `keyEncipherment`, `keyCertSign`, `cRLSign`, etc. |
| EKU          | `extendedKeyUsage`       | Narrower purposes like `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`. |
| SAN          | `subjectAltName`         | Alternative identities: DNS names, IPs, URIs, emails. Required for TLS hostnames. |
| SKI          | `subjectKeyIdentifier`   | Unique identifier derived from the cert’s public key. |
| AKI          | `authorityKeyIdentifier` | Links cert to its issuer (usually matches the issuer’s SKI). |

-----------------------------------------------------------------------------------------------------------------------
[Gitlab](https://github.com/gliese667-dev/notes/blob/main/GitLab.md) © 2025 by [Ole Martin Håland](https://github.com/gliese667-dev) is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
