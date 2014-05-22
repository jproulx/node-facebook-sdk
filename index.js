/*jshint node: true */
"use strict";
var domain      = require('domain');
var qs          = require('querystring');
var createError = require('custom-error-generator');
var assert      = require('assert');
var codes = {
    'OAuthException' : 'OAuthException',
    '102' : 'API Session',
    '1'   : 'API Unknown',
    '2'   : 'API Service',
    '4'   : 'API Too Many Calls',
    '17'  : 'API User Too Many Calls',
    '10'  : 'API Permission Denied',
    '341' : 'Application Limit Reached',
    '506' : 'Duplicate Post'
};
var FacebookSDKError = createError('FacebookSDKError');
var FacebookSDK = function (config) {
    assert.ok(config.appID, 'The Facebook SDK requires an application ID');
    assert.ok(config.secret, 'The Facebook SDK requires an application secret token');
    this.appID  = config.appID;
    this.secret = config.secret;
    this.cache  = { };
    this.debug  = config.logger || console;
    this.data   = { };
    // Fetch the details for this application on startup
    this.getApplicationDetails(function (error, data) {
        if (!error) {
            this.data = data;
        }
    });
};
FacebookSDK.prototype.createAppSecretProof = function (access_token) {
    var crypto = require('crypto');
    return crypto.createHmac('SHA256', this.secret).update(access_token).digest('base64');
};
FacebookSDK.prototype.isolate = function FBSDKIsolate (execute, callback) {
    var d = domain.create();
    return d.on('error', function (error) {
        console.error(error.stack || error.message || error);
        if (callback && typeof callback === 'function') {
            return callback.call(this, error, null);
        }
    }.bind(this)).run(function (){
        return execute.call(this, d);
    }.bind(this));
};
FacebookSDK.prototype.request = function FBSDKRequest (options, callback) {
    this.debug.info('FacebookSDK.request');
    return this.isolate(function (d) {
        var protocol = require('https');
        var request = {
            'host'   : 'graph.facebook.com',
            'port'   : 443,
            'path'   : options.path,
            'method' : options.method,
            'agent'  : false
        };
        var params = qs.stringify(options.params);
        if (request.method === 'POST') {
            request.headers = {
                'Content-Type'   : 'application/x-www-form-urlencoded',
                'Content-Length' : params.length
            };
        } else {
            request.path += '?' + params;
        }
        var client = protocol.request(request);
        client.on('response', function (response) {
            var chunks = [];
            var code = response.statusCode;
            var headers = response.headers;
            response.setEncoding('utf8');
            response.on('data', function (chunk) {
                chunks.push(chunk);
            });
            response.on('end', d.bind(function () {
                var body        = chunks.join();
                var contentType = headers['content-type'].split(';');
                var response    = null;
                switch (contentType[0]) {
                    case 'text/javascript':
                    response = JSON.parse(body);
                    break;
                    case 'text/plain':
                    response = qs.parse(body);
                    break;
                }
                if (code >= 400) {
                    var error = new FacebookSDKError(response.error.message, {
                        'code' : response.error.code,
                        'type' : response.error.type
                    });
                    return callback.call(this, error, null);
                }
                return callback.call(this, null, response);
            }.bind(this)));
        }.bind(this));
        // Send POST headers if specified
        if (request.method.toUpperCase() == 'POST') {
            client.write(params);
        }
        return client.end();
    }, callback);
};
FacebookSDK.prototype.getApplicationAccessToken = function FBSDKGetApplicationAccessToken (callback) {
    this.debug.info('FacebookSDK.getApplicationAccessToken');
    return this.isolate(function (d) {
        // If we already have the token cached, just use it
        if (this.cache.applicationAccessToken) {
            return callback.call(this, null, this.cache.applicationAccessToken);
        }
        var options = {
            'method' : 'GET',
            'path'   : '/oauth/access_token',
            'params' : {
                'client_id'     : this.appID,
                'client_secret' : this.secret,
                'grant_type'    : 'client_credentials'
            },
        };
        return this.request(options, d.intercept(function (data) {
            this.cache.applicationAccessToken = data.access_token;
            return callback.call(this, null, data.access_token);
        }.bind(this)));
    }, callback);
};
FacebookSDK.prototype.sendApplicationAPIRequest = function FBSDKSendApplicationAPIRequest (options, callback) {
    this.debug.info('FacebookSDK.sendApplicationAPIRequest');
    return this.isolate(function (d) {
        return this.getApplicationAccessToken(d.intercept(function (applicationAccessToken) {
            options.params = options.params || {};
            options.params.access_token = applicationAccessToken;
            return this.request(options, d.bind(callback));
        }.bind(this)));
    }, callback);
};
FacebookSDK.prototype.getApplicationDetails = function FBSDKGetApplicationDetails (callback) {
    this.debug.info('FacebookSDK.getApplicationDetails');
    return this.isolate(function (d) {
        if (this.data.id) {
            return callback.call(this, null, this.data);
        }
        var options = {
            'path'   : '/' + this.appID,
            'method' : 'GET'
        };
        return this.sendApplicationAPIRequest(options, d.bind(callback));
    }, callback);
};
FacebookSDK.prototype.sendApplicationNotification = function FBSDKSendApplicationNotification (recipientID, href, ref, template, callback) {
    this.debug.info('FacebookSDK.sendApplicationNotification');
    assert.ok(recipientID, 'recipientID is required');
    assert.ok(href, 'href is required');
    assert.equal(typeof href, 'string', 'href should be a string');
    assert.ok(template, 'template is required');
    assert.equal(typeof template, 'string', 'template should be a string');
    return this.isolate(function (d) {
        var options = {
            'method' : 'POST',
            'path'   : ['/', recipientID, '/notifications'].join(''),
            'params' : {
                'href'     : href,
                'ref'      : ref,
                'template' : template,
            }
        };
        return this.sendApplicationAPIRequest(options, d.bind(callback));
    }, callback);
};
FacebookSDK.prototype.deleteAllApplicationScores = function FBSDKDeleteAllApplicationScores (callback) {
    this.debug.info('FacebookSDK.deleteAllApplicationScores');
    return this.isolate(function (d) {
        var options = {
            'method' : 'DELETE',
            'path'   : ['/', this.appID, '/scores'].join(''),
            'params' : {}
        };
        return this.sendApplicationAPIRequest(options, d.bind(callback));
    }, callback);
};
/**
 * Follows the recommended settings for establishing a channelURL for the JS SDK
 *
 * @note    https://developers.facebook.com/blog/post/2011/08/02/how-to--optimize-social-plugin-performance/
 *
 * @public
 * @static
 * @param   {Object}    request
 * @param   {Object}    response
 */
FacebookSDK.channelMiddleware = function FBSDKChannelMiddleware (request, response) {
    var crypto  = require('crypto');
    var expires = 60 * 60 * 24 * 365;
    var body    = '<script src="//connect.facebook.net/en_US/all.js"></script>';
    var date    = new Date(Date.now() + (expires * 1000)).toUTCString();
    var md5     = crypto
        .createHash('md5')
        .update(body, 'utf8')
        .digest('hex');
    // Set all response headers
    response.set({
        'Pragma'        : 'public',
        'Cache-Control' : 'public, maxage=' + expires,
        'Expires'       : date,
        'Etag'          : md5
    });
    return response.send(body);
};

module.exports = FacebookSDK;
