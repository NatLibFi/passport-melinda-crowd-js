import {readFileSync} from 'fs';
import passport from 'passport';
import {v4 as uuid} from 'uuid';
import {BasicStrategy} from 'passport-http';
import {Strategy as BearerStrategy} from 'passport-http-bearer';
import {clone} from '@natlibfi/melinda-commons';
import {createLogger} from '@natlibfi/melinda-backend-commons';

import {
  BearerCredentialsStrategy as CrowdCredentialsStrategy,
  BearerTokenStrategy as CrowdTokenStrategy
} from '@natlibfi/passport-atlassian-crowd';


export function generatePassportMiddlewares({crowd, localUsers}) {
  const logger = createLogger();

  if (crowd.url && crowd.appName && crowd.appPassword) {
    return initCrowdMiddlewares();
  }

  if (typeof localUsers === 'string') {
    return initLocalMiddlewares();
  }

  throw new Error('No configuration for passport strategies');

  function initCrowdMiddlewares() {
    passport.use(new CrowdCredentialsStrategy(crowd));
    passport.use(new CrowdTokenStrategy({
      ...crowd,
      useCache: crowd.useCache, fetchGroupMembership: crowd.fetchGroupMembership
    }));

    logger.info('Enabling Crowd passport strategies');

    return {
      credentials: passport.authenticate('atlassian-crowd-bearer-credentials', {session: false}),
      token: passport.authenticate('atlassian-crowd-bearer-token', {session: false})
    };
  }

  function initLocalMiddlewares() {
    const users = parseUsers();
    const localSessions = {};

    passport.use(new BasicStrategy(localBasicCallback));
    passport.use(new BearerStrategy(localBearerCallback));

    logger.info('Enabling local passport strategies');

    return {
      credentials: passport.authenticate('basic', {session: false}),
      token: passport.authenticate('bearer', {session: false})
    };

    function parseUsers() {
      if (localUsers.startsWith('file://')) {
        const str = readFileSync(localUsers.replace(/^file:\/\//u, ''), 'utf8');
        return parse(str);
      }

      return parse(localUsers);

      function parse(str) {
        try {
          return JSON.parse(str);
        } catch (err) {
          throw new Error('Could not parse local users');
        }
      }
    }

    function localBasicCallback(reqUsername, reqPassword, done) {
      const user = users.find(({id, password}) => reqUsername === id && reqPassword === password);

      if (user) {
        const token = getToken();
        done(null, token);
        return;
      }

      done(null, false);

      function getToken() {
        const existingToken = Object.keys(localSessions).find(token => {
          const userInfo = localSessions[token];
          return userInfo.id === user.username;
        });

        if (existingToken) {
          return existingToken;
        }

        const newToken = uuid().replace(/-/gu, '');
        localSessions[newToken] = removePassword(user); // eslint-disable-line functional/immutable-data

        return newToken;

        function removePassword(userData) {
          return Object.keys(clone(userData)).filter(k => k !== 'password').reduce((acc, key) => ({...acc, [key]: userData[key]}), {});
        }
      }
    }

    function localBearerCallback(reqToken, done) {
      const entry = Object.entries(localSessions).find(([token]) => reqToken === token);

      if (entry) {
        done(null, entry[1]);
        return;
      }

      done(null, false);
    }
  }
}
