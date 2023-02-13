# potoo-ldap-phonebook2

This project expose wazo directory throught ldap protocol.

## Installation
You can donwload the binary from the release page and execute it on your wazo server.

## Usage
It is possible to filter the results returned by the plugin according to the `cn` and `telephoneNumber` attributes.

The base DN of the search must be the following: `ou=phonebook,cn=potoo,dc=pm`

Below are query example made with ldap search:
```
ldapsearch -x -b "ou=phonebook,cn=potoo,dc=pm" -H ldap://localhost:1389 -D uid=potoo -w MiCht+47QF496zoeyxa= "(cn=*test*)"
ldapsearch -x -b "ou=phonebook,cn=potoo,dc=pm" -H ldap://localhost:1389 -D uid=potoo -w MiCht+47QF496zoeyxa= "(telphoneNumber=800*)"
```

## Arguments
The help menu is available here :
```
Options:
      --version                      Show version number               [boolean]
  -v, --logLevel                     Set the loglevel [string] [default: "info"]
      --wazoHost, --wh               Set the wazo host
                                                 [string] [default: "localhost"]
      --wazoUser, --wu               Set the wazo username
                                      [string] [default: "potoo-ldap-phonebook"]
      --wazoPassword, --wp           Set the wazo password              [string]
      --ldapUser, --lu               Set the ldap user (required to bind to the
                                     server)     [string] [default: "uid=potoo"]
      --ldapPassword, --lw           Set the ldap password (required to bind to
                                     the server)
                                      [string] [default: "MiCht+47QF496zoeyxa="]
      --ldapPort, --lp               Set the ldap server listen port
                                                      [string] [default: "1389"]
      --ldapMaxResult, --lmr         Set the ldap max result returned by the
                                     server             [string] [default: "50"]
      --skipCertificateError, --sce  Skip the certificate errors when connecting
                                     to wazo          [boolean] [default: false]
  -l, --language                     Set the language used to display messages
                                  [string] [choices: "en", "fr"] [default: "en"]
      --help                         Show help                         [boolean]
 ```
 
## Limitaiton
* Only basic ldap filters are supported
* Only simple bind request are supported, ( no NTLM bind request, no digest MD5 bind request, no GSSAPI bind request )
