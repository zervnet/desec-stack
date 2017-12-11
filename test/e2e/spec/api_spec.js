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

            var example_records = {
                'A': ['1.2.3.4', '192.168.0.4', '10.1.1.1'],
                'AAAA': ['feed:dead::beef', 'bad:c00f:fee::', 'feed:bade:affe:dead::beef'],
                'CNAME': ['mycname.local.', 'differentcname.local.', 'another.cname.local'],
                'MX': [
                    '10 mail.domain.local.',
                    '10 smtp.domain.local.',
                    '5 alt2.aspmx.l.domain.local.',
                ],
                'SPF': [
                    '"v=spf1 include:tinned-software.net ~all"',
                    '"v=spf1 mx a include:tinned-software.net ~all"',
                    '"v=spf1 mx a ~all"',
                ],
                'CAA': [
                    '128 issue "domain.local"',
                    '128 iodef "mailto:mail@domain.local"',
                    '1 issue "letsencrypt.org"',
                    '1 iodef "mailto:info@domain.local"',
                ],
            };

            var ttls = [10, 60, 3600, 3600 * 24 * 7];

            describe("no subname", function () {

                Object.keys(example_records).forEach(function(recordType) {

                    describe("type: " + recordType, function () {

                        describe('can create record sets', function () {
                            var domain = 'e2etest-' + require("uuid").v4() + '.local';

                            before(function () {
                                return tools.registerDomain(domain).then(function () {
                                    return expect(chakram.post('/domains/' + domain + '/rrsets/', {
                                        subname: "",
                                        type: recordType,
                                        records: [example_records[recordType][0]],
                                        ttl: 60,
                                    })).to.have.status(201);
                                });
                            });

                            it('propagate to the API', function () {
                                return expect(chakram.get('/domains/' + domain + '/rrsets/.../' + recordType + '/')).to.have.json('records', [example_records[recordType][0]]);
                            });

                            it('propagate to pdns', function () {
                                expect(chakram.resolve(domain, recordType)).to.have.members([example_records[recordType][0]]);
                                return chakram.wait();
                            });

                        });

                    });

                });

            });

        });

        it("provides an index page", function () {
            var response = chakram.get('/');
            return expect(response).to.have.status(200);
        });

    });

});
