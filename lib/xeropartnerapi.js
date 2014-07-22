var oauth = require('oauth');
var fs = require('fs');


var request_token_url = 'https://api-partner.network.xero.com/oauth/RequestToken';
var request_auth_url = 'https://api.xero.com/oauth/Authorize?oauth_token=';
var access_token_url = 'https://api-partner.network.xero.com/oauth/AccessToken';
var api_url = 'https://api-partner.network.xero.com/api.xro/2.0/';
var oauth_signature_method = 'RSA-SHA1';
var oauth_version = '1.0';


/**
 * [XeroPartnerApi wrapper library for Xero Partner API Common calls wrapping up all the ]
 * @param {[object]} config [an object containing the required configuration parameters example below]
 *
 *  {
 *      ssl: {
 *               keypath: '/path/to/ssl/clientAuth.key',
 *               certpath:'/path/to/ssl/clientAuth.crt'
 *           },
 *      oauth: {
 *          consumer: {
 *              secret: 'ABC',
 *              key: 'XZY',
 *              rsa: {
 *                  keypath: '/path/to/oauth-signing-private.key'
 *              }
 *          },
 *          callback: 'http://somehost/xero/callback'
 *      }
 *  }
 *
 * 
 */
exports.XeroPartnerApi = function (config){
    
    var ssl_client_key = fs.readFileSync(config.ssl.keypath, {encoding: "utf8"});
    var ssl_client_cert = fs.readFileSync(config.ssl.certpath, {encoding: "utf8"});
    var signing_private_key = fs.readFileSync(config.oauth.consumer.rsa.keypath, {encoding: "utf8"});

    this._consumer = new oauth.OAuth(
        request_token_url,
        access_token_url,
        config.oauth.consumer.key,
        signing_private_key,
        oauth_version,
        config.oauth.callback,
        oauth_signature_method
        );

    this._consumer.setHttpOptions({
        key : ssl_client_key,
        cert : ssl_client_cert
    });


};

/**
 * [getRequestToken get a request token to refer a user to obtain a access token]
 * @param  {Function} callback [function (err, oauth_token, oauth_token_secret)]
 * @return {[undefined]}
 */
exports.XeroPartnerApi.prototype.getRequestToken = function(callback) {

    var done = function (err, oauth_token, oauth_token_secret, results) {
        if (err){
            callback(err);
            return;
        } else {
            callback(undefined, oauth_token, oauth_token_secret, request_auth_url + oauth_token);
        }
    };

    this._consumer.getOAuthRequestToken(done);
};


//

/**
 * [getAccessToken given a request token, secret and verifier get an access token and secret and its oauth session particulars]
 * @param  {[string]}   request_token          [a token obtained from a getRequestToken call that you sent a user to Xero with]
 * @param  {[string]}   request_token_secret   [the request tokens secret that you obtained when you called getRequestToken ]
 * @param  {[string]}   request_token_verifier [the verifer you obtained from the call back when the user was redirected from Xero]
 * @param  {Function} callback                 [function (err, oauth_token, oauth_token_secret, oauth_expires_in, oauth_session_handle, oauth_authorization_expires_in)]
 * @return {[undefined]}
 */
exports.XeroPartnerApi.prototype.getAccessToken = function(request_token, request_token_secret, request_token_verifier, callback) {

    var done = function (err, oauth_token, oauth_token_secret, results) {
        if (err){
            callback(err);
            return;
        } else {
            callback(undefined,
                    oauth_token,
                    oauth_token_secret,
                    results.oauth_expires_in,
                    results.oauth_session_handle,
                    results.oauth_authorization_expires_in);
        }
    };

    this._consumer.getOAuthAccessToken(request_token, request_token_secret, request_token_verifier, done);

};

exports.XeroPartnerApi.prototype.refreshAccessToken = function(access_token, access_token_secret, session_handle, callback) {

    var done = function (err, oauth_token, oauth_token_secret, results) {
        if (err){
            callback(err);
            return;
        } else {
            callback(undefined,
                    oauth_token,
                    oauth_token_secret,
                    results.oauth_expires_in,
                    results.oauth_session_handle,
                    results.oauth_authorization_expires_in);
        }
    };

    this._consumer.refreshOAuthAccessToken(access_token, access_token_secret, session_handle, done);

}

exports.XeroPartnerApi.prototype.makeSecureGet = function(access_token, access_token_secret, url, callback) {

    var splitAndDecodeErrorData = function(data) {
        var ret = {};
        var bits = data.split('&');
        for (var i = 0; i < bits.length; i++) {
            var pair = bits[i].split('=');
            ret[pair[0]] = unescape(pair[1]);
        }
        return ret;
    };

    var done = function (err, data, response){
        err.data = splitAndDecodeErrorData(err.data);;
        callback(err, data, response);
    };
    this._consumer.get(url, access_token, access_token_secret, done);
};