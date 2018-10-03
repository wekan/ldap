import {slug, getLdapUsername, getLdapUserUniqueID, syncUserData, addLdapUser} from './sync';
import LDAP from './ldap';
import { log_debug, log_info, log_warn, log_error } from './logger';

function fallbackDefaultAccountSystem(bind, username, password) {
  if (typeof username === 'string') {
    if (username.indexOf('@') === -1) {
      username = {username};
    } else {
      username = {email: username};
    }
  }

  log_info('Fallback to default account system: ', username );

  const loginRequest = {
    user: username,
    password: {
      digest: SHA256(password),
      algorithm: 'sha-256',
    },
  };
  log_debug('Fallback options: ', loginRequest);

  return Accounts._runLoginHandlers(bind, loginRequest);
}

Accounts.registerLoginHandler('ldap', function(loginRequest) {
  if (!loginRequest.ldap || !loginRequest.ldapOptions) {
    return undefined;
  }

  log_info('Init LDAP login', loginRequest.username);

  if (LDAP.settings_get('LDAP_ENABLE') !== true) {
    return fallbackDefaultAccountSystem(this, loginRequest.username, loginRequest.ldapPass);
  }

  const self = this;
  const ldap = new LDAP();
  let ldapUser;

  try {
    ldap.connectSync();
    const users = ldap.searchUsersSync(loginRequest.username);

    if (users.length !== 1) {
      log_info('Search returned', users.length, 'record(s) for', loginRequest.username);
      throw new Error('User not Found');
    }

    if (ldap.authSync(users[0].dn, loginRequest.ldapPass) === true) {
      if (ldap.isUserInGroup(loginRequest.username, users[0])) {
        ldapUser = users[0];
      } else {
        throw new Error('User not in a valid group');
      }
    } else {
      log_info('Wrong password for', loginRequest.username);
    }
  } catch (error) {
    log_error(error);
  }

  if (ldapUser === undefined) {
    if (LDAP.settings_get('LDAP_LOGIN_FALLBACK') === true) {
      return fallbackDefaultAccountSystem(self, loginRequest.username, loginRequest.ldapPass);
    }

    throw new Meteor.Error('LDAP-login-error', `LDAP Authentication failed with provided username [${ loginRequest.username }]`);
  }

  // Look to see if user already exists
  let userQuery;

  const Unique_Identifier_Field = getLdapUserUniqueID(ldapUser);
  let user;

  if (Unique_Identifier_Field) {
    userQuery = {
      'services.ldap.id': Unique_Identifier_Field.value,
    };

    log_info('Querying user');
    log_debug('userQuery', userQuery);

    user = Meteor.users.findOne(userQuery);
  }

  let username;

  if (LDAP.settings_get('LDAP_USERNAME_FIELD') !== '') {
    username = slug(getLdapUsername(ldapUser));
  } else {
    username = slug(loginRequest.username);
  }

  if (!user) {
    userQuery = {
      username,
    };

    log_debug('userQuery', userQuery);

    user = Meteor.users.findOne(userQuery);
  }

  // Login user if they exist
  if (user) {
    if (user.ldap !== true && LDAP.settings_get('LDAP_MERGE_EXISTING_USERS') !== true) {
      log_info('User exists without "ldap: true"');
      throw new Meteor.Error('LDAP-login-error', `LDAP Authentication succeded, but there's already an existing user with provided username [${ username }] in Mongo.`);
    }

    log_info('Logging user');

    const stampedToken = Accounts._generateStampedLoginToken();
    const update_data = {
      $push: {
        'services.resume.loginTokens': Accounts._hashStampedToken(stampedToken),
      },
    };

    if( LDAP.settings_get('LDAP_SYNC_GROUP_ROLES') === true ) {
      log_debug('Updating Groups/Roles');
		    const groups = ldap.getUserGroups(username, ldapUser);

		    if( groups.length > 0 ) {
        Roles.setUserRoles(user._id, groups );
        log_info(`Updated roles to:${  groups.join(',')}`);
		    }
    }

    Meteor.users.update(user._id, update_data );

    syncUserData(user, ldapUser);

    if (LDAP.settings_get('LDAP_LOGIN_FALLBACK') === true) {
      Accounts.setPassword(user._id, loginRequest.ldapPass, {logout: false});
    }

    return {
      userId: user._id,
      token: stampedToken.token,
    };
  }

  log_info('User does not exist, creating', username);

  if (LDAP.settings_get('LDAP_USERNAME_FIELD') === '') {
    username = undefined;
  }

  if (LDAP.settings_get('LDAP_LOGIN_FALLBACK') !== true) {
    loginRequest.ldapPass = undefined;
  }

  // Create new user
  const result = addLdapUser(ldapUser, username, loginRequest.ldapPass);

  if( LDAP.settings_get('LDAP_SYNC_GROUP_ROLES') === true ) {
    const groups = ldap.getUserGroups(username, ldapUser);
    if( groups.length > 0 ) {
      Roles.setUserRoles(result.userId, groups );
      log_info(`Set roles to:${  groups.join(',')}`);
    }
  }


  if (result instanceof Error) {
    throw result;
  }

  return result;
});
