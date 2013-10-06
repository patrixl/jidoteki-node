# Description:
#   Build virtual appliances using Jidoteki
#   http://jidoteki.com
#   Copyright (c) 2013 Alex Williams, Unscramble <license@unscramble.jp>

###
 * Jidoteki - http://jidoteki.com
 * Build virtual appliances using Jidoteki
 * Copyright (c) 2013 Alex Williams, Unscramble <license@unscramble.jp>
###

crypto    = require 'crypto'
armrest   = require 'armrest'

jido = exports ? this

jido.settings   =
  endpoint:   'https://api.beta.jidoteki.com'
  userid:     process.env.JIDOTEKI_USERID || 'change me'
  apikey:     process.env.JIDOTEKI_APIKEY || 'change me'
  useragent:  'nodeclient-jidoteki/0.5'
  token:      null

jido.api        = armrest.client jido.settings.endpoint

module.exports.makeHMAC = (string, callback) =>
  hmac = crypto.createHmac('sha256', jido.settings.apikey).update(string).digest 'hex'
  callback(hmac)

module.exports.getToken = (callback) =>
  resource = '/auth/user'
  @makeHMAC "POST#{jido.settings.endpoint}#{resource}", (signature) ->
    jido.api.post
      url: resource
      headers:
        'X-Auth-Uid': jido.settings.userid
        'X-Auth-Signature': signature
        'User-Agent': jido.settings.useragent
        'X-Api-Version': 1
      complete: (err, res, data) ->
        if data.success
          jido.settings.token = data.success.content
          setTimeout ->
            jido.settings.token = null
          , 27000000 # Expire the token after 7.5 hours
        callback data

module.exports.getData = (type, resource, callback) =>
  @makeHMAC "#{type.toUpperCase()}#{jido.settings.endpoint}#{resource}", (signature) ->
    jido.api.get
      url: resource
      headers:
        'X-Auth-Token': jido.settings.token
        'X-Auth-Signature': signature
        'User-Agent': jido.settings.useragent
        'X-Api-Version': 1
      complete: (err, res, data) ->
        if err
          jido.settings.token = null if data.error and data.error.message is 'Unable to authenticate'
        callback data

module.exports.makeRequest = (type, resource, callback) =>
  if jido.settings.token isnt null
    @getData type, resource, (data) ->
      callback data
  else
    @getToken (result) ->
      jido.getData type, resource, (data) ->
        callback data
