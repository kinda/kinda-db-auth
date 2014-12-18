'use strict';

var KindaClass = require('kinda-class');
var util = require('kinda-util').create();
var httpClient = require('kinda-http-client').create();

var Auth = KindaClass.extend('Auth', function() {
  Object.defineProperty(this, 'token', {
    get: function() {
      return this._token;
    },
    set: function(token) {
      this._token = token;
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
    this.token = item.id;
    return item;
  };

  this.signInWithToken = function *(token) {
    if (!token) throw new Error('token is missing');
    var url = this.baseURL + '/tokens/' + token;
    var res = yield httpClient.get(url);
    if (res.statusCode === 403) return false;
    if (res.statusCode !== 200)
      throw new Error('unexpected HTTP status code (' + res.statusCode + ')');
    var item = res.body;
    if (item.id !== token)
      throw new Error('assertion error (item.id !== token)');
    if (item.expirationTime != null)
      if (item.expirationTime <= 0) return false;
    this.token = token;
    return item;
  };

  this.signOut = function *() {
    if (!this.token) return;
    var url = this.baseURL + '/tokens/' + this.token;
    try {
      yield httpClient.del({ url: url, json: false });
    } catch (err) {
      util.error(err);
    }
    this.token = undefined;
  };
});

module.exports = Auth;
