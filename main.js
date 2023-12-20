async function main() {

  const winston = require('winston');
  const yargs = require('yargs');
  const https = require('node:https');
  const { WazoApiClient } = require('@wazo/sdk');
  const ldap = require('ldapjs');

  const argv = yargs
    .option('logLevel', {
      alias: 'v',
      description: 'Set the loglevel',
      type: 'string',
      default: 'info'
    })
    .option('wazoHost', {
      alias: 'wh',
      description: 'Set the wazo host',
      type: 'string',
      default: 'localhost'
    })
    .option('wazoUser', {
      alias: 'wu',
      description: 'Set the wazo username',
      type: 'string',
      default: 'potoo-ldap-phonebook'
    })
    .option('wazoPassword', {
      alias: 'wp',
      description: 'Set the wazo password',
      type: 'string',
    })
    .option('ldapUser', {
      alias: 'lu',
      description: 'Set the ldap user (required to bind to the server)',
      type: 'string',
      default: 'uid=potoo'
    })
    .option('ldapPassword', {
      alias: 'lw',
      description: 'Set the ldap password (required to bind to the server)',
      type: 'string',
      default: 'MiCht+47QF496zoeyxa='
    })
    .option('ldapPort', {
      alias: 'lp',
      description: 'Set the ldap server listen port',
      type: 'string',
      default: '1389'
    })
    .option('ldapMaxResult', {
      alias: 'lmr',
      description: 'Set the ldap max result returned by the server',
      type: 'string',
      default: '50'
    })
    .option('skipCertificateError', {
      alias: 'sce',
      description: 'Skip the certificate errors when connecting to wazo',
      type: 'boolean',
      default: false
    })
    .option('language', {
      alias: 'l',
      description: 'Set the language used to display messages',
      type: 'string',
      choices: ['en', 'fr'],
      default: 'en'
    })
    .help()
    .argv;

  const loglevel = argv.logLevel;
  const wazo_host = argv.wazoHost;
  const wazo_user = argv.wazoUser;
  const wazo_password = argv.wazoPassword;
  const ldap_user = argv.ldapUser;
  const ldap_password = argv.ldapPassword;
  const ldap_port = argv.ldapPort;
  const ldap_max_result = argv.ldapMaxResult;
  const language = argv.language;

  const logger = winston.createLogger({
    transports: [
      new winston.transports.Console({
        level: loglevel,
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss.SSS'
          }),
          winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
        )
      })
    ]
  });

  const translations = {
    'en': {
      no_search: 'Enter something to search',
    },
    'fr': {
      no_search: 'Spécifiez quoi chercher',
    }
  };

  const options = {
    rejectUnauthorized: false
  };

  if (argv.skipCertificateError) {
    custom_agent = new https.Agent(options);
  } else {
    custom_agent = null
  }

  const client = new WazoApiClient({
    server: wazo_host,
    agent: custom_agent,
    clientId: 'potoo-ldap-phonebook',
    isMobile: false,
  });

  client.setOnRefreshToken((newToken, newSession) => {
    logger.info('wazo-auth token refreshed');
  });

  let session;

  try {
    session = await client.auth.logIn({
      username: wazo_user,
      password: wazo_password
    });
  } catch (error) {
    if (typeof error.status !== 'undefined') {
      logger.error('wazo authentification fail status code: ' + error.status);
    } else {
      logger.error(error)
    }
    process.exit(1);
  }

  client.setToken(session.token);
  client.setRefreshToken(session.refreshToken);

  logger.info('connected to wazo-auth');

  const server = ldap.createServer();

  server.on('error', (error) => {
    logger.error('ldapjs error:', error);
  });

  server.listen(ldap_port, () => {
    logger.info('ldap server listening at ' + server.url);
  });

  function authorize(req, res, next) {
    const isSearch = (req instanceof ldap.SearchRequest);
    if (req.connection.ldap.bindDN.equals('cn=anonymous')) {
      logger.info(req.logId + ' anonymous search refused');
      return next(new ldap.InvalidCredentialsError()); // disallow anonymous search
    }
    return next();
  }

  server.bind(ldap_user, (req, res, next) => {
    const username = req.dn.toString();
    const password = req.credentials;

    if (username !== ldap_user || password !== ldap_password) {
      logger.info(req.logId + ' ldap authentification fail for user: ' + req.dn.toString());
      return next(new ldap.InvalidCredentialsError());
    } else {
      logger.verbose(req.logId + ' ldap authentification: ' + req.dn.toString());
    }
    res.end();
    return next();
  });

  // return the first matched search string extracted from ldap filter
  function extract_search_from_filter(filters, logId) {

    let dird_search_string = null;
    logger.verbose(logId + ' filter: ' + filters);
    logger.verbose(logId + ' filter.type: ' + filters.type);
    logger.verbose(logId + ' filter.attribute: ' + filters.attribute);

    // if filter is like (!(cn=Ben*))
    if (filters.type === 'not') {
      logger.verbose(logId + ' skiped "not" filter ( wazo limitation ): ' + filters.toString());
    }
    // if filter is (cn=*)
    if (filters.type === 'present') {
      logger.verbose(logId + ' skiped "present" filter ( wazo limitation ): ' + filters.toString());
    }

    // if filter is like (&(objectclass=*)(cn=Ben*)) or (|(objectclass=*)(cn=Ben*))
    if (filters.type === 'and' || filters.type === 'or') {
      logger.verbose(logId + ' ' + filters.type);
      for (const filter of filters.filters) {
        logger.verbose(logId + ' ' + filter);
        if (dird_search_string === null) {
          dird_search_string = extract_search_from_filter(filter, logId)
        } else {
          logger.verbose(logId + ' skiped because not the first match: ' + filter.toString());
        }
      }
    }

    // if filter is like cn=ta
    if (filters.type === 'equal') {
      if (filters.attribute === 'cn' || filters.attribute === 'telephonenumber') {
        if (dird_search_string === null) {
          // if searched number is a internal number
          const internal_number_regex = /^\d{2,6}$/;
          if (internal_number_regex.test(filters.toString().split("=")[1].slice(0, -1))) {
            logger.info(logId + ' skiped because this is a internal phone number: ' + filters.toString());
          } else {
            dird_search_string = filters.toString().split("=")[1].slice(0, -1);
          }
        } else { logger.verbose(logId + ' skiped because not the first match: ' + filters.toString()); }
      } else { logger.verbose(logId + ' skiped because not a supported attribut: ' + filters.attribute); }
    }
    // if filter is like cn=*ta*,  cn=ta* or cn=*ta
    if (filters.type === 'substring') {
      if (filters.attribute === 'cn' || filters.attribute === 'telephonenumber') {
        // if filter is like cn=*ta*
        if (filters.any.toString() !== '') {
          if (dird_search_string === null) {
            dird_search_string = filters.any[0];
          } else { logger.verbose(logId + ' skiped because not the first match: ' + filters.toString()); }
        } else if (typeof filters.initial !== 'undefined') {
          // if filter is like cn=ta*
          if (dird_search_string === null) {
            dird_search_string = filters.initial;
          } else { logger.info(logId + ' skiped because not the first match: ' + filters.toString()); }
        } else if (typeof filters.final !== 'undefined') {
          // if filter is like cn=*ta
          if (dird_search_string === null) {
            dird_search_string = filters.final;
          } else { logger.verbose(logId + ' skiped because not the first match: ' + filters.toString()); }
        }
      } else {
        logger.verbose(logId + ' skiped because not a supported attribut: ' + filters.toString());
      }
    }
    logger.verbose(logId + ' dird_search_string before return: ' + dird_search_string);
    return dird_search_string;
  }

  server.search('ou=phonebook,cn=potoo,dc=pm', authorize, (req, res, next) => {

    logger.verbose(req.logId + ' filter: ' + req.filter);
    logger.verbose(req.logId + ' filter.type: ' + req.filter.type);
    logger.verbose(req.logId + ' filter.attribute: ' + req.filter.attribute);

    if (req.filter.toString() === '(&(objectclass=*)(cn=*))') {

      const obj = {
        dn: req.dn.toString(),
        attributes: {
          cn: translations[language].no_search,
          telehponeNumber: ''
        }
      };
      res.send(obj);
      res.end();
      return next();
    }

    dird_search_string = extract_search_from_filter(req.filter, req.logId)

    if (dird_search_string !== null) {
      logger.info(req.logId + ' new wazo-dird search: ' + dird_search_string);

      let dird_search_results;

      try {
        dird_search_results = (async () => {
          const result = await client.dird.search('default', dird_search_string);
          return result;
        })();
      } catch (error) {
        if (typeof error.status !== 'undefined') {
          logger.error(req.logId + ' wazo search fail status code: ' + error.status);
        } else {
          logger.error(error)
        }
      }

      dird_search_results.then(dird_search_results => {
        //console.log(dird_search_results);
        let nb_ldap_result = ldap_max_result;
        for (const dird_search_result of dird_search_results) {
          if (nb_ldap_result > 1) {
            if (dird_search_result['numbers'].toString() !== '') {
              for (const dird_search_result_number of dird_search_result['numbers']) {
                let name_sufixe = ''
                if (dird_search_result_number.label === 'secondary') {
                  name_sufixe = ' - mobile'
                } else {
                  name_sufixe = ''
                }
                const entry = {
                  dn: req.dn.toString(),
                  attributes: {
                    cn: dird_search_result['name'] + name_sufixe,
                    telephoneNumber: dird_search_result_number.number,
                  }
                }
                nb_ldap_result--;
                res.send(entry);
              }
            }
          }
        }
        res.end();
        return next();
      }).catch(error => {
        logger.error(error);
        res.end();
        return next();
      });
    }
    else {
      res.end();
      return next();
    }
  });
}
main();
