'use strict';

var KindaClass = require('kinda-class');
var log = require('kinda-log').create();
var httpClient = require('kinda-http-client').create();

var Auth = KindaClass.extend('Auth', function() {
  Object.defineProperty(this, 'authorization', {
    get: function() {
      return this._authorization;
    },
    set: function(authorization) {
      this._authorization = authorization;
    }
  });

  this.signInWithCredentials = function *(username, password, expirationTime) {
    if (!username) throw new Error('username is missing');
    if (!password) throw new Error('password is missing');
    var url = this.baseURL + '/tokens';
    var body = { username: username, password: password };
    if (expirationTime) body.expirationTime = expirationTime;
    var params = { method: 'POST', url: url, body: body };
    var res = yield httpClient.request(params);
    if (res.statusCode === 403) return false;
    if (res.statusCode !== 201)
      throw new Error('unexpected HTTP status code (' + res.statusCode + ')');
    var item = res.body;
    if (!item.id)
      throw new Error('assertion error (!item.id)');
    this.authorization = item.id;
    return item;
  };

  this.signInWithPreviousAuthorization = function *(authorization) {
    if (!authorization) throw new Error('authorization is missing');
    var url = this.baseURL + '/tokens/' + authorization;
    var res = yield httpClient.get(url);
    if (res.statusCode === 404) return false;
    if (res.statusCode !== 200)
      throw new Error('unexpected HTTP status code (' + res.statusCode + ')');
    var item = res.body;
    if (item.id !== authorization)
      throw new Error('assertion error (item.id !== authorization)');
    if (item.expirationTime != null)
      if (item.expirationTime <= 0) return false;
    this.authorization = authorization;
    return item;
  };

  this.signOut = function *() {
    if (!this.authorization) return;
    var url = this.baseURL + '/tokens/' + this.authorization;
    try {
      yield httpClient.del({ url: url, json: false });
    } catch (err) {
      log.error(err);
    }
    this.authorization = undefined;
  };
});

module.exports = Auth;
