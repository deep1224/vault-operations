"use strict"
/********************************************************
 * Project:     vault-access
 * ------------------------------------------------------
 * File:        index.js
 * Description: The execution starts from this page
 * Created:     23-May-2021
 * Modified:    23-May-2021
 * Author:      Deepak Giri
 *
 * ******************************************************/

const vault_auth_client = require('./vault_auth/auth');
const configs_class = require('./vault_auth/libs/attributes');
const request = require('request');
const app_config = require('./config/app_config');
const file_name = app_config.get("project_name") + ' > index.js > ';
const urlParser = require('url');

class vault_auth {
    constructor(args) {
        const _vault = args;
        console.log(file_name + 'constructor: input arguments', (_vault.hasOwnProperty("view_additional_logs") ? _vault : ""));
        app_config.set("view_additional_logs", (_vault.hasOwnProperty("view_additional_logs") ? _vault.view_additional_logs : app_config.get("view_additional_logs")));
        console.log(file_name + 'constructor: view_additional_logs is set to', app_config.get("view_additional_logs"));

        const vault_address = _vault["url"];
        const addr = urlParser.parse(vault_address)
        const protocol = addr.protocol
        const vault_domain = addr.hostname;
        const vault_port = addr.port;
        const vault_extn = addr.pathname + "/";

        const vault_path = _vault.path;
        const vault_version = _vault.version;
        this.vault_namespace = _vault.namespace;
        const vault_role = _vault.role;
        const vault_ssl = _vault.hasOwnProperty("ssl") ? _vault.ssl : app_config.get("ssl");
        const ssl_reject_un_authorized = _vault.hasOwnProperty("ssl_reject_un_authorized") ? _vault.ssl_reject_un_authorized : app_config.get("ssl_reject_un_authorized");
        const cert_file_path = _vault.hasOwnProperty("cert_file_path") ? _vault.cert_file_path : app_config.get("cert_file_path");

        const ldap_id = vault.ldap_id;
        const password = _vault.password;
        const role_id = _vault.role_id;
        const secret_id = _vault.secret_id;
        const login_type = _vault.login_type;

        const login_method = login_type === 'aws'? "" : login_type;


        const vault_login_url = this.vault_namespace + '/auth' + login_method + vault_path + '/login';
        vault_login_url = login_type === 'ldap'? vault_login_url + '/' + ldap_id : vault_login_url;

        let configs = new configs_class({
            ssl: vault_ssl,
            host: vault_domain,
            extn: vault_extn,
            port: vault_port,
            api_version: vault_version,
            vault_app_name: vault_role,
            vault_login_url: vault_login_url,
            ssl_reject_un_authorized: ssl_reject_un_authorized,
            cert_file_path: cert_file_path,
            ldap_id: ldap_id,
            password: password,
            role_id: role_id,
            secret_id: secret_id,
            login_type: login_type
        });
        let valid_configs = configs.validate_attributes();
        if (!valid_configs.valid) {
            throw valid_configs.details;
        }

        this.vault_client = new vault_auth_client(configs.get_attributes());
        const vault_host = protocol + "//" + addr.host;
        this.vault_rw_url = (_vault.folder != '') ?
            (vault_host + vault_extn + vault_version + '/secret' + vault_path + _vault.folder) :
            (vault_host + vault_extn + vault_version + '/secret' + vault_path);
    }

    generate_token() {
        console.log(file_name + 'generate_token: begin');
        var self = this;
        return new Promise(function (resolve, reject) {
            self.vault_client.authenticate()
                .then((success) => {
                    var client_token = success.auth.client_token;
                    if (client_token == undefined || client_token == "" ||
                        client_token == "undefined" || client_token == null) {
                        console.log(file_name + 'generate_token: does not contain token');
                        resolve('');
                    } else {
                        console.log(file_name + 'generate_token: token has been generated - ' + (app_config.get("view_additional_logs") ? client_token : ""));
                        resolve(client_token);
                    }
                })
                .catch((fail) => {
                    console.log(file_name + 'generate_token: error - ' + JSON.stringify(fail));
                    reject(fail);
                });
        });
    }

    read_vault_data(client_token = null) {
        console.log(file_name + 'read_vault_data: begin');
        var self = this;
        return new Promise(function (resolve, reject) {
            if (client_token) {
                console.log(file_name + 'read_vault_data: received client token - ' + (app_config.get("view_additional_logs") ? client_token : ""));
                self.read_request(client_token).then((res) => { resolve(res) }, (err) => { reject(err) });
            }
            else {
                console.log(file_name + 'read_vault_data: generating new client token');
                self.generate_token().then(function (client_token) {
                    if (client_token !== '') {
                        self.read_request(client_token).then((res) => { resolve(res) }, (err) => { reject(err) });
                    } else {
                        reject('read_vault_data: could not generate the token');
                        console.log(file_name + 'read_vault_data: could not generate the token');
                    }
                }, function (err) {
                    console.log(file_name + 'read_vault_data: error while generating token - ' + JSON.stringify(err));
                    reject(err);
                });
            }
        });
    }

    read_request(token) {
        console.log(file_name + 'read_request: begin');
        var self = this;
        return new Promise(function (resolve, reject) {
            var headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.vault_namespace
            };
            var options = {
                url: self.vault_rw_url,
                headers: headers
            };
            console.log(file_name + 'read_request: options - ' + (app_config.get("view_additional_logs") ? JSON.stringify(options) : ""));

            request(options, function (error, response, body) {
                if (!error && response.statusCode == 200) {
                    console.log(file_name + 'read_request: body - ' + (app_config.get("view_additional_logs") ? JSON.stringify(body) : ""));
                    let result = JSON.parse(body);
                    resolve(result.data);
                } else {
                    console.log(file_name + 'read_request: could not generate the token');
                    reject('read_request: could not generate the token');
                }
            });
        });
    }

    write_to_vault(data) {
        console.log(file_name + 'write_to_vault: begin');
        var self = this;
        return new Promise(function (resolve, reject) {
            self.generate_token().then(function (client_token) {
                if (client_token !== '') {
                    var headers = {
                        'X-Vault-Token': client_token,
                        'X-Vault-Namespace': self.vault_namespace
                    };
                    var options = {
                        method: 'POST',
                        url: self.vault_rw_url,
                        headers: headers,
                        body: JSON.stringify(data)
                    };

                    request(options, function (error, response, body) {
                        if (!error && response.statusCode == 204) {
                            //204 No Content - Server successfully processed the request but not returning any content
                            console.log(file_name + 'write_to_vault: data is successfully written into vault');
                            resolve('write_to_vault: data is successfully written into vault');
                        } else {
                            console.log(file_name + 'write_to_vault: write error - ' + JSON.stringify(error));
                            reject(error);
                        }
                    });
                } else {
                    console.log(file_name + 'write_to_vault: could not generate the token');
                    reject('write_to_vault: could not generate the token');
                }
            }, function (err) {
                console.log(file_name + 'write_to_vault: error - ' + JSON.stringify(err));
                reject(err);
            });
        });
    }

}

module.exports = vault_auth;