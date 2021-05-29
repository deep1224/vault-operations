# vault-operations
If you are using hashicorp vault (https://www.vaultproject.io/) for storing your secrets and you want to access them from AWS Cloud Services like EC2 instance or Lambda functions, then this package helps you to programatically access the vault secrets securely.

## Getting Started

This is the first version released and works for limited scope. If there are any issues, please post a comment.

### Install

```
$npm install vault-operations
```

### How to use
Include the module vault-access and instantiate a new object of va and pass all the required parameters.
```
const va = require('vault-operations');

var vao = new va({
    "url": "<vault url example: https://abc.com/xyz/txt/123 or http://10.100.10.100:8080/default/abc >",
    "namespace": "<namespace - do not prefix or postfix with '/'>",
    "version": "<vault version - set 'v1' for default>",
    "path": "<path to your secrets in vault server - prefix with '/'>",
    "folder": "<folder path if any, where credentials are stored - prefix with '/'>",
    "role": "<vault role>"
});
```

To read secrets from vault
```
vao.read_vault_data().then(function (result) {
    console.log(result);
}, function (err) {
    console.log(err);
});
```

To write secrets to vault
```
var secrets={ username:"abc", pass:"xyz" }
vao.write_to_vault(secrets).then(function (result) {
    console.log(result);
}, function (err) {
    console.log(err);
});
```
