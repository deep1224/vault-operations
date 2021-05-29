"use strict"
/********************************************************
 * Project:     vault-access
 * ------------------------------------------------------
 * File:        vault_auth/auth.js
 * Description: Authenticates the source
 * Created:     23-May-2021
 * Modified:    23-May-2021
 * Author:      Deepak Giri
 *
 * ******************************************************/

const AWS = require('aws-sdk');
const aws_signed_request = require('./libs/aws_signed_request');
const request = require('request');
const app_config = require('../config/app_config');
const file_name = app_config.get("project_name") + ' > authentication.js > ';

class vault_aws_auth {

    constructor(args) {
        this.configs = args;
    }

    get_options(creds) {
        console.log(file_name + 'get_options: begin');
        let options = {
            url: this.configs.uri,
            followAllRedirects: this.configs.follow_all_redirects,
        };

        if (this.configs.login_type === 'ldap') {
            options = { ...options, ...{ body: this.JSON.stringify({ password: this.configs.password }) } }
        }
        else if (this.configs.login_type === 'approle') {
            options = {
                ...options, ...{
                    body: this.JSON.stringify({
                        "role_id": this.configs.role_id,
                        "secret_id": this.configs.secret_id
                    })
                }
            }
        } else if (this.configs.login_type === 'aws') {
            let signed_request = new aws_signed_request({ host: this.configs.host, vault_app_name: this.configs.vault_app_name });
            options = { ...options, ...{ body: this.JSON.stringify({ body: JSON.stringify(signed_request.get_signed_configs(creds)) }) } }
        }

        if (this.configs.ssl_certificate) {
            options['cert'] = this.configs.ssl_certificate;
        }
        if (!this.configs.ssl_reject_un_authorized) {
            process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = app_config.get("NODE_TLS_REJECT_UNAUTHORIZED");
        }
        console.log(file_name + 'get_options: generated options - ' + (app_config.get("view_additional_logs") ? JSON.stringify(options) : ""));
        console.log(file_name + 'get_options: end');
        return options;
    }

    authenticate() {
        console.log(file_name + 'authenticate: begin');
        if (this.configs.login_type === 'ldap' || this.configs.login_type === 'approle') {
            return this.authbyProvidedCreds()
        } else if (this.configs.login_type === 'aws') {
            return this.authbyAws()
        }
    }

    authbyProvidedCreds() {
        console.log(file_name + 'authbyProvidedCreds: begin');
        return new Promise((resolve, reject) => {
            let options = this.get_options(creds);
            console.log(file_name + 'authbyProvidedCreds: extracted creds - ' + (app_config.get("view_additional_logs") ? JSON.stringify(creds) : ""));
            request.post(options, function (err, res, body) {
                if (err) {
                    console.log(file_name + 'authbyProvidedCreds: error - ' + JSON.stringify(err));
                    reject(err);
                }
                else {
                    console.log(file_name + 'authbyProvidedCreds: response body - ' + (app_config.get("view_additional_logs") ? JSON.stringify(body) : ""));
                    let result = JSON.parse(body);
                    if (result.errors) {
                        console.log(file_name + 'authbyProvidedCreds: result.errors');
                        reject(result);
                    }
                    else {
                        console.log(file_name + 'authbyProvidedCreds: success');
                        resolve(result);
                    }
                }
                console.log(file_name + 'authbyProvidedCreds: end');
            });
        })
    }

    authbyAws() {
        console.log(file_name + 'authbyAws: begin');
        const provider_chain = new AWS.CredentialProviderChain();
        return provider_chain.resolvePromise().then(creds => {
            console.log(file_name + 'authbyAws: extracted AWS.CredentialProviderChain creds - ' + (app_config.get("view_additional_logs") ? JSON.stringify(creds) : ""));
            return new Promise((resolve, reject) => {
                let options = this.get_options(creds);
                request.post(options, function (err, res, body) {
                    if (err) {
                        console.log(file_name + 'authbyAws: error - ' + JSON.stringify(err));
                        reject(err);
                    }
                    else {
                        console.log(file_name + 'authbyAws: response body - ' + (app_config.get("view_additional_logs") ? JSON.stringify(body) : ""));
                        let result = JSON.parse(body);
                        if (result.errors) {
                            console.log(file_name + 'authbyAws: result.errors');
                            reject(result);
                        }
                        else {
                            console.log(file_name + 'authbyAws: success');
                            resolve(result);
                        }
                    }
                    console.log(file_name + 'authbyAws: end');
                });
            });
        })
    }
}

module.exports = vault_aws_auth;
