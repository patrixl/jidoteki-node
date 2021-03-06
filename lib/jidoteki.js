// Generated by CoffeeScript 1.6.3
/*
 * Jidoteki - http://jidoteki.com
 * Build virtual appliances using Jidoteki
 * Copyright (c) 2013 Alex Williams, Unscramble <license@unscramble.jp>
*/


(function() {
  var armrest, crypto, jido,
    _this = this;

  crypto = require('crypto');

  armrest = require('armrest');

  jido = typeof exports !== "undefined" && exports !== null ? exports : this;

  jido.settings = {
    endpoint: 'https://api.jidoteki.com',
    userid: process.env.JIDOTEKI_USERID || 'change me',
    apikey: process.env.JIDOTEKI_APIKEY || 'change me',
    useragent: 'nodeclient-jidoteki/0.1.0',
    token: null
  };

  jido.api = armrest.client(jido.settings.endpoint);

  module.exports.makeHMAC = function(string, callback) {
    var hmac;
    hmac = crypto.createHmac('sha256', jido.settings.apikey).update(string).digest('hex');
    return callback(hmac);
  };

  module.exports.getToken = function(callback) {
    var resource;
    resource = '/auth/user';
    return _this.makeHMAC("POST" + jido.settings.endpoint + resource, function(signature) {
      return jido.api.post({
        url: resource,
        headers: {
          'X-Auth-Uid': jido.settings.userid,
          'X-Auth-Signature': signature,
          'User-Agent': jido.settings.useragent,
          'Accept-Version': 1
        },
        complete: function(err, res, data) {
          if (data.success) {
            jido.settings.token = data.success.content;
            setTimeout(function() {
              return jido.settings.token = null;
            }, 27000000);
          }
          return callback(data);
        }
      });
    });
  };

  module.exports.getData = function(type, resource, callback) {
    return _this.makeHMAC("" + (type.toUpperCase()) + jido.settings.endpoint + resource, function(signature) {
      return jido.api.get({
        url: resource,
        headers: {
          'X-Auth-Token': jido.settings.token,
          'X-Auth-Signature': signature,
          'User-Agent': jido.settings.useragent,
          'Accept-Version': 1
        },
        complete: function(err, res, data) {
          if (err) {
            if (data.error && data.error.message === 'Unable to authenticate') {
              jido.settings.token = null;
            }
          }
          return callback(data);
        }
      });
    });
  };

  module.exports.makeRequest = function(type, resource, callback) {
    if (jido.settings.token !== null) {
      return _this.getData(type, resource, function(data) {
        return callback(data);
      });
    } else {
      return _this.getToken(function(result) {
        return jido.getData(type, resource, function(data) {
          return callback(data);
        });
      });
    }
  };

}).call(this);
