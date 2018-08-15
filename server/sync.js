
import _ from 'underscore';
import LDAP from './ldap';
import { log_debug, log_info, log_warn, log_error } from './logger';

export function slug(text) {
  if (LDAP.settings_get('UTF8_Names_Slugify') !== true) {
    return text;
  }
  text = slugify(text, '.');
  return text.replace(/[^0-9a-z-_.]/g, '');
}

function templateVarHandler (variable, object) {

  const templateRegex = /#{([\w\-]+)}/gi;
  let match = templateRegex.exec(variable);
  let tmpVariable = variable;

  if (match == null) {
    if (!object.hasOwnProperty(variable)) {
      return;
    }
    return object[variable];
  } else {
    while (match != null) {
      const tmplVar = match[0];
      const tmplAttrName = match[1];

      if (!object.hasOwnProperty(tmplAttrName)) {
        return;
      }

      const attrVal = object[tmplAttrName];
      tmpVariable = tmpVariable.replace(tmplVar, attrVal);
      match = templateRegex.exec(variable);
    }
    return tmpVariable;
  }
}

export function getPropertyValue(obj, key) {
  try {
    return _.reduce(key.split('.'), (acc, el) => acc[el], obj);
  } catch (err) {
    return undefined;
  }
}


export function getLdapUsername(ldapUser) {
  const usernameField = LDAP.settings_get('LDAP_Username_Field');

  if (usernameField.indexOf('#{') > -1) {
    return usernameField.replace(/#{(.+?)}/g, function(match, field) {
      return ldapUser[field];
    });
  }

  return ldapUser[usernameField];
}


export function getLdapUserUniqueID(ldapUser) {
  let Unique_Identifier_Field = LDAP.settings_get('LDAP_Unique_Identifier_Field');

  if (Unique_Identifier_Field !== '') {
    Unique_Identifier_Field = Unique_Identifier_Field.replace(/\s/g, '').split(',');
  } else {
    Unique_Identifier_Field = [];
  }

  let User_Search_Field = LDAP.settings_get('LDAP_User_Search_Field');

  if (User_Search_Field !== '') {
    User_Search_Field = User_Search_Field.replace(/\s/g, '').split(',');
  } else {
    User_Search_Field = [];
  }

  Unique_Identifier_Field = Unique_Identifier_Field.concat(User_Search_Field);

  if (Unique_Identifier_Field.length > 0) {
    Unique_Identifier_Field = Unique_Identifier_Field.find((field) => {
      return !_.isEmpty(ldapUser._raw[field]);
    });
    if (Unique_Identifier_Field) {
		    log_debug(`Identifying user with: ${  Unique_Identifier_Field}`);
      Unique_Identifier_Field = {
        attribute: Unique_Identifier_Field,
        value: ldapUser._raw[Unique_Identifier_Field].toString('hex'),
      };
    }
    return Unique_Identifier_Field;
  }
}

export function getDataToSyncUserData(ldapUser, user) {
  const syncUserData = LDAP.settings_get('LDAP_Sync_User_Data');
  const syncUserDataFieldMap = LDAP.settings_get('LDAP_Sync_User_Data_FieldMap').trim();

  const userData = {};

  if (syncUserData && syncUserDataFieldMap) {
    const whitelistedUserFields = ['email', 'name', 'customFields'];
    const fieldMap = JSON.parse(syncUserDataFieldMap);
    const emailList = [];
    _.map(fieldMap, function(userField, ldapField) {
		    log_debug(`Mapping field ${ldapField} -> ${userField}`);
      switch (userField) {
      case 'email':
        if (!ldapUser.hasOwnProperty(ldapField)) {
          log_debug(`user does not have attribute: ${ ldapField }`);
          return;
        }

        if (_.isObject(ldapUser[ldapField])) {
          _.map(ldapUser[ldapField], function(item) {
            emailList.push({ address: item, verified: true });
          });
        } else {
          emailList.push({ address: ldapUser[ldapField], verified: true });
        }
        break;

      default:
        const [outerKey, innerKeys] = userField.split(/\.(.+)/);

        if (!_.find(whitelistedUserFields, (el) => el === outerKey)) {
          log_debug(`user attribute not whitelisted: ${ userField }`);
          return;
        }

        if (outerKey === 'customFields') {
          let customFieldsMeta;

          try {
            customFieldsMeta = JSON.parse(LDAP.settings_get('Accounts_CustomFields'));
          } catch (e) {
            log_debug('Invalid JSON for Custom Fields');
            return;
          }

          if (!getPropertyValue(customFieldsMeta, innerKeys)) {
            log_debug(`user attribute does not exist: ${ userField }`);
            return;
          }
        }

        const tmpUserField = getPropertyValue(user, userField);
        const tmpLdapField = templateVarHandler(ldapField, ldapUser);

        if (tmpLdapField && tmpUserField !== tmpLdapField) {
          // creates the object structure instead of just assigning 'tmpLdapField' to
          // 'userData[userField]' in order to avoid the "cannot use the part (...)
          // to traverse the element" (MongoDB) error that can happen. Do not handle
          // arrays.
          // TODO: Find a better solution.
          const dKeys = userField.split('.');
          const lastKey = _.last(dKeys);
          _.reduce(dKeys, (obj, currKey) =>
            (currKey === lastKey)
              ? obj[currKey] = tmpLdapField
              : obj[currKey] = obj[currKey] || {}
            , userData);
          log_debug(`user.${ userField } changed to: ${ tmpLdapField }`);
        }
      }
    });

    if (emailList.length > 0) {
      if (JSON.stringify(user.emails) !== JSON.stringify(emailList)) {
        userData.emails = emailList;
      }
    }
  }

  const uniqueId = getLdapUserUniqueID(ldapUser);

  if (uniqueId && (!user.services || !user.services.ldap || user.services.ldap.id !== uniqueId.value || user.services.ldap.idAttribute !== uniqueId.attribute)) {
    userData['services.ldap.id'] = uniqueId.value;
    userData['services.ldap.idAttribute'] = uniqueId.attribute;
  }

  if (user.ldap !== true) {
    userData.ldap = true;
  }

  if (_.size(userData)) {
    return userData;
  }
}


export function syncUserData(user, ldapUser) {
  log_info('Syncing user data');
  log_debug('user', {'email': user.email, '_id': user._id});
  log_debug('ldapUser', ldapUser.object);

  if (LDAP.settings_get('LDAP_Username_Field') !== '') {
    const username = slug(getLdapUsername(ldapUser));
    if (user && user._id && username !== user.username) {
      log_info('Syncing user username', user.username, '->', username);
      Meteor.users.findOne({ _id: user._id }, { $set: { username }});
    }
  }
}

export function addLdapUser(ldapUser, username, password) {
  const uniqueId = getLdapUserUniqueID(ldapUser);

  const userObject = {
  };

  if (username) {
    userObject.username = username;
  }

  const userData = getDataToSyncUserData(ldapUser, {});

  if (userData && userData.emails && userData.emails[0] && userData.emails[0].address) {
    if (Array.isArray(userData.emails[0].address)) {
      userObject.email = userData.emails[0].address[0];
    } else {
      userObject.email = userData.emails[0].address;
    }
  } else if (ldapUser.mail && ldapUser.mail.indexOf('@') > -1) {
    userObject.email = ldapUser.mail;
  } else if (LDAP.settings_get('LDAP_Default_Domain') !== '') {
    userObject.email = `${ username || uniqueId.value }@${ LDAP.settings_get('LDAP_Default_Domain') }`;
  } else {
    const error = new Meteor.Error('LDAP-login-error', 'LDAP Authentication succeded, there is no email to create an account. Have you tried setting your Default Domain in LDAP Settings?');
    log_error(error);
    throw error;
  }

  log_debug('New user data', userObject);

  if (password) {
    userObject.password = password;
  }

  try {
    // This creates the account with password service
    userObject._id = Accounts.createUser(userObject);
    // Add the services.ldap identifiers
    Meteor.users.update({ _id:  userObject._id }, {
		    $set: {
		        'services.ldap': { id: uniqueId.value },
		        'emails.0.verified': true,
		        ldap: true,
		    }});
  } catch (error) {
    log_error('Error creating user', error);
    return error;
  }

  syncUserData(userObject, ldapUser);

  return {
    userId: userObject._id,
  };
}

export function importNewUsers(ldap) {
  if (LDAP.settings_get('LDAP_Enable') !== true) {
    log_error('Can\'t run LDAP Import, LDAP is disabled');
    return;
  }

  if (!ldap) {
    ldap = new LDAP();
    ldap.connectSync();
  }

  let count = 0;
  ldap.searchUsersSync('*', Meteor.bindEnvironment((error, ldapUsers, {next, end} = {}) => {
    if (error) {
      throw error;
    }

    ldapUsers.forEach((ldapUser) => {
      count++;

      const uniqueId = getLdapUserUniqueID(ldapUser);
      // Look to see if user already exists
      const userQuery = {
        'services.ldap.id': uniqueId.value,
      };

      log_debug('userQuery', userQuery);

      let username;
      if (LDAP.settings_get('LDAP_Username_Field') !== '') {
        username = slug(getLdapUsername(ldapUser));
      }

      // Add user if it was not added before
      let user = Meteor.users.findOne(userQuery);

      if (!user && username && LDAP.settings_get('LDAP_Merge_Existing_Users') === true) {
        const userQuery = {
          username,
        };

        log_debug('userQuery merge', userQuery);

        user = Meteor.users.findOne(userQuery);
        if (user) {
          syncUserData(user, ldapUser);
        }
      }

      if (!user) {
        addLdapUser(ldapUser, username);
      }

      if (count % 100 === 0) {
        log_info('Import running. Users imported until now:', count);
      }
    });

    if (end) {
      log_info('Import finished. Users imported:', count);
    }

    next(count);
  }));
}

function sync() {
  if (LDAP.settings_get('LDAP_Enable') !== true) {
    return;
  }

  const ldap = new LDAP();

  try {
    ldap.connectSync();

    let users;
    if (LDAP.settings_get('LDAP_Background_Sync_Keep_Existant_Users_Updated') === true) {
      users = Meteor.users.find({ 'services.ldap': { $exists: true }});
    }

    if (LDAP.settings_get('LDAP_Background_Sync_Import_New_Users') === true) {
      importNewUsers(ldap);
    }

    if (LDAP.settings_get('LDAP_Background_Sync_Keep_Existant_Users_Updated') === true) {
      users.forEach(function(user) {
        let ldapUser;

        if (user.services && user.services.ldap && user.services.ldap.id) {
          ldapUser = ldap.getUserByIdSync(user.services.ldap.id, user.services.ldap.idAttribute);
        } else {
          ldapUser = ldap.getUserByUsernameSync(user.username);
        }

        if (ldapUser) {
          syncUserData(user, ldapUser);
        } else {
          log_info('Can\'t sync user', user.username);
        }
      });
    }
  } catch (error) {
    log_error(error);
    return error;
  }
  return true;
}

const jobName = 'LDAP_Sync';

const addCronJob = _.debounce(Meteor.bindEnvironment(function addCronJobDebounced() {
  if (LDAP.settings_get('LDAP_Background_Sync') !== true) {
    log_info('Disabling LDAP Background Sync');
    if (SyncedCron.nextScheduledAtDate(jobName)) {
      SyncedCron.remove(jobName);
    }
    return;
  }

  if (LDAP.settings_get('LDAP_Background_Sync_Interval')) {
    log_info('Enabling LDAP Background Sync');
    SyncedCron.add({
      name: jobName,
      schedule: (parser) => parser.text(LDAP.settings_get('LDAP_Background_Sync_Interval')),
      job() {
        sync();
      },
    });
    SyncedCron.start();
  }
}), 500);

Meteor.startup(() => {
  Meteor.defer(() => {
    LDAP.settings_get('LDAP_Background_Sync', addCronJob);
    LDAP.settings_get('LDAP_Background_Sync_Interval', addCronJob);
  });
});
