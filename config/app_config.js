"use strict"
/********************************************************
 * Project:     vault-access
 * ------------------------------------------------------
 * File:        config/app_config.js
 * Description: Application configurations
 * Created:     22-Apr-2020
 * Modified:    23-May-2021
 * Author:      Deepak Giri
 *
 * ******************************************************/

var app_configurations = {
    "project_name": "vault-access",
    "view_additional_logs": false,
    "ssl": true,
    "ssl_reject_un_authorized": true,
    "NODE_TLS_REJECT_UNAUTHORIZED": '0',
    "cert_file_path": ""
}
const file_name = app_configurations["project_name"] + ' > app_config.js > ';

module.exports = {
    set: function (key, value) { 
        app_configurations[key] = value; 
        console.log(file_name + `set: setting app config ${key} by value - ${app_configurations[key]}`);
    },
    get: function (key) {
        return app_configurations[key]
    }
}