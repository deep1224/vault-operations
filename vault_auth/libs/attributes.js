"use strict"
/********************************************************
 * Project:     vault-access
 * ------------------------------------------------------
 * File:        vault_auth/libs/attributes.js
 * Description: Validate all the input attributes
 * Created:     23-May-2021
 * Modified:    23-May-2021
 * Author:      Deepak Giri
 *
 * ******************************************************/

const fs = require('fs');
const validator = require('validator');
const app_config = require('../../config/app_config');
const file_name = app_config.get("project_name") + ' > attributes.js > ';

class attributes {
    constructor(args) {
        this.ssl = args.ssl || false;
        this.host = args.host;
        this.extn = args.extn;
        this.port = parseInt(args.port) || '';  // 8200;
        this.api_version = args.api_version || 'v1';
        this.vault_login_url = args.vault_login_url || 'auth/aws/login';
        this.vault_app_name = args.vault_app_name || process.env.AWS_LAMBDA_FUNCTION_NAME;
        this.follow_all_redirects = args.follow_all_redirects || true;
        this.cert_file_path = args.cert_file_path;
        this.ssl_reject_un_authorized = args.ssl_reject_un_authorized;
        this.ldap_id = args.ldap_id;
        this.password = args.password;
        this.role_id = args.role_id;
        this.secret_id = args.secret_id;
        this.login_type = args.login_type;
    }

    validate_attributes() {
        console.log(file_name + 'validate_attributes: begin');

        if (typeof this.ssl !== 'boolean')
            return {
                valid: false,
                details: 'ssl must be boolean true or false'
            };
        if (typeof this.ssl_reject_un_authorized !== 'boolean')
            return {
                valid: false,
                details: 'ssl_reject_un_authorized must be boolean true or false'
            };
        if (!validator.isFQDN(this.host) && !validator.isIP(this.host)) {
            return {
                valid: false,
                details: 'host must be an IP address or fully qualified domain name'
            };
        }
        if (this.port !== '') {
            if (typeof this.port !== 'number' || this.port < 1 || this.port > 65536) {
                return {
                    valid: false,
                    details: 'port is a number and must be within 1 to 65536'
                };
            }
        }
        if (this.extn !== '') {
            if (typeof this.extn !== 'string') {
                return {
                    valid: false,
                    details: 'url path must be string'
                };
            }
        }
        if (this.api_version !== 'v1' && this.api_version !== 'v2') {
            return {
                valid: false,
                details: 'API version is either v1 or v2'
            };
        }
        if (typeof this.vault_login_url !== 'string') {
            return {
                valid: false,
                details: 'vault_login_url must be string'
            };
        }
        if (typeof this.vault_app_name !== 'string') {
            return {
                valid: false,
                details: 'vault_app_name must be string'
            };
        }
        if (typeof this.follow_all_redirects !== 'boolean') {
            return {
                valid: false,
                details: 'follow_all_redirects must be boolean'
            };
        }
        
        console.log(file_name + 'validate_attributes: end');
        return { valid: true };
    }

    get_attributes() {
        console.log(file_name + 'get_attributes: begin');
        this.vault_login_url = encodeURI(this.vault_login_url);
        let url_prefix = this.ssl ? 'https://' : 'http://';
        if (this.extn !== '' && this.port == '') {
            this.uri = url_prefix + this.host + this.extn + this.api_version + '/' + this.vault_login_url;
        } else {
            this.uri = url_prefix + this.host + ':' + this.port + '/' + this.api_version + '/' + this.vault_login_url;
        }

        if (this.cert_file_path) {
            this.ssl_certificate = fs.readFileSync(this.cert_file_path, 'utf8');
        }
        let final_attributes = {
            ssl: this.ssl,
            host: this.host,
            port: this.port,
            api_version: this.api_version,
            vault_login_url: this.vault_login_url,
            vault_app_name: this.vault_app_name,
            uri: this.uri,
            follow_all_redirects: this.follow_all_redirects,
            ssl_reject_un_authorized: this.ssl_reject_un_authorized
        };
        if (this.cert_file_path)
            final_attributes['ssl_certificate'] = this.ssl_certificate;

        console.log(file_name + 'get_attributes: final attributes - ' + (app_config.get("view_additional_logs") ? JSON.stringify(final_attributes) : ""));
        console.log(file_name + 'get_attributes: end');
        return final_attributes;
    }

}

module.exports = attributes;
