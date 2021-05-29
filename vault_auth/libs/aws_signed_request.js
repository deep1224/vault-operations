"use strict"
/********************************************************
 * Project:     vault-access
 * ------------------------------------------------------
 * File:        vault_auth/libs/aws_signed_request.js
 * Description: Gets aws signed request
 * Created:     23-May-2021
 * Modified:    23-Apr-2020
 * Author:      Deepak Giri
 *
 * ******************************************************/

const aws4 = require('aws4');
const app_config = require('../../config/app_config');
const file_name = app_config.get("project_name") + ' > aws_signed_request.js > ';

class aws_signed_request {
    constructor(args) {
        this.vault_host = args.host;
        this.vault_app_name = args.vault_app_name;
        this.aws_request_url = 'https://sts.amazonaws.com/';
        this.aws_request_body = 'Action=GetCallerIdentity&Version=2011-06-15';
    }
    get_signed_request(creds) {
        console.log(file_name + 'get_signed_request: begin');
        let aws_creds = {
            accessKeyId: creds.accessKeyId,
            secretAccessKey: creds.secretAccessKey
        };
        if (creds.sessionToken) {
            aws_creds.sessionToken = creds.sessionToken;
        }
        console.log(file_name + 'get_signed_request: aws_creds - ' + (app_config.get("view_additional_logs") ? JSON.stringify(aws_creds) : ""));

        if (this.vault_host) {
            var signed_request = aws4.sign({
                service: 'sts',
                headers: { 'X-Vault-AWS-IAM-Server-ID': this.vault_host },
                body: this.aws_request_body
            }, aws_creds);

        }
        else {
            var signed_request = aws4.sign({ service: 'sts', body: this.aws_request_body }, aws_creds);
        }
        console.log(file_name + 'get_signed_request: signed_request - ' + (app_config.get("view_additional_logs") ? JSON.stringify(signed_request) : ""));
        console.log(file_name + 'get_signed_request: end');
        return signed_request;
    }

    get_signed_headers(creds) {
        console.log(file_name + 'get_signed_headers: begin');
        let signed_request = this.get_signed_request(creds);
        let headers = signed_request.headers;
        for (let header in headers) {
            if (typeof headers[header] === 'number') {
                headers[header] = headers[header].toString();
            }
            headers[header] = [headers[header]];
        }
        console.log(file_name + 'get_signed_headers: signed_headers - ' + (app_config.get("view_additional_logs") ? JSON.stringify(headers) : ""));
        console.log(file_name + 'get_signed_headers: end');
        return headers;
    }

    get_signed_configs(creds) {
        console.log(file_name + 'get_signed_configs: begin');
        let headers = this.get_signed_headers(creds);
        let encrypted_signed_config = {
            role: this.vault_app_name,
            iam_http_request_method: 'POST',
            iam_request_url: new Buffer(this.aws_request_url).toString('base64'),
            iam_request_body: new Buffer(this.aws_request_body).toString('base64'),
            iam_request_headers: new Buffer(JSON.stringify(headers)).toString('base64')
        };
        console.log(file_name + 'get_signed_configs: encrypted_signed_config - ' + (app_config.get("view_additional_logs") ? JSON.stringify(encrypted_signed_config) : ""));
        console.log(file_name + 'get_signed_configs: end');
        return encrypted_signed_config
    }
}
module.exports = aws_signed_request;
