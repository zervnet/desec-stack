var chakram = require("./../setup.js").chakram;
var tools = require("./../tools.js").tools;
var expect = chakram.expect;

describe("API", function () {

    var URL = 'https://www/api/v1';

    before(function () {
        chakram.setRequestSettings({
            headers: {
                'Host': 'desec.' + process.env.DESECSTACK_DOMAIN,
            },
            followRedirect: false,
            baseUrl: 'https://www/api/v1',
        });
    });

    it("provides an index page", function () {
        var response = chakram.get('/');
        return expect(response).to.have.status(200);
    });

    // note that registration and login functionality is tested in dyndns_spec.js

    var email = require("uuid").v4() + '@e2etest.local';
    describe("[user " + email + "]", function () {

        before(function() {
            return tools.registerAndLogin(email);
        });

        describe("domains", function() {

            it("can be created", function() {
                var domain = 'e2etest-' + require("uuid").v4() + '.local';
                return expect(chakram.post('/domains/', {'name': domain})).to.have.status(201);
            });

            var domain = 'e2etest-' + require("uuid").v4() + '.local';
            describe("[domain " + domain + "]", function() {

                before(function() {
                    return expect(chakram.post('/domains/', {'name': domain})).to.have.status(201);
                });

                it("can be deleted", function() {
                    return expect(chakram.delete('/domains/' + domain + '/')).to.have.status(204);
                });

            });

        });

        describe("rrsets", function () {

            var domain = 'e2etest-' + require("uuid").v4() + '.local';
            before(function () {

            });

        });

        it("provides an index page", function () {
            var response = chakram.get('/');
            return expect(response).to.have.status(200);
        });

    });

});
