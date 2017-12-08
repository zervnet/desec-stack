var chakram = require("./setup.js").chakram;
var expect = chakram.expect;

function registerAndLogin(email) {
    // register a user that we can login and work with
    var password = require("uuid").v4();

    // logout first
    chakram.setRequestHeader('Authorization', '');

    return chakram.post('/auth/users/create/', {
        "email": email,
        "password": password,
    }).then(function () {
        return chakram.post('/auth/token/create/', {
            "email": email,
            "password": password,
        }).then(function (loginResponse) {
            expect(loginResponse).to.have.status(200);
            me.current_token = loginResponse.body.auth_token;
            expect(me.current_token).to.match(/^[a-z0-9]{40}$/);
            chakram.setRequestHeader('Authorization', 'Token ' + me.current_token);
        });
    });
}

var me = {
    registerAndLogin: registerAndLogin,
    current_token: '',
};

exports.tools = me;
