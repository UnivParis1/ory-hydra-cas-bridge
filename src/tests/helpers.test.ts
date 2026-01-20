import * as assert from "assert"
import * as helpers from "../helpers.ts"

const h = helpers.export_for_tests

const casAuthSuccessResponse = `
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationSuccess>
        <cas:user>prigaux</cas:user>
        <cas:proxies>
            <cas:proxy>https://compte-test.univ-paris1.fr/compte/login/cas_pgtCallback</cas:proxy>
        </cas:proxies>
        <cas:attributes>
            <cas:mail>Pascal.Rigaux@univ-paris1.fr</cas:mail>
            <cas:authenticationDate>2022-07-03T21:15:34.458182Z</cas:authenticationDate>
            <cas:eduPersonAffiliation>member</cas:eduPersonAffiliation>
            <cas:eduPersonAffiliation>employee</cas:eduPersonAffiliation>
            <cas:eduPersonAffiliation>staff</cas:eduPersonAffiliation>
            <cas:displayName>Pascal Rigaux</cas:displayName>
            <cas:givenName>Pascal</cas:givenName>
            <cas:userAgent>Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0</cas:userAgent>
            <cas:uid>prigaux</cas:uid>
            <cas:serverIpAddress>172.20.0.1</cas:serverIpAddress>
            <cas:memberOf>cn=applications.www.admin-www,ou=groups,dc=univ-paris1,dc=fr</cas:memberOf>
            <cas:memberOf>cn=applications.www.webmestre.all,ou=groups,dc=univ-paris1,dc=fr</cas:memberOf>
            <cas:memberOf>cn=applications.www.webmestre.miniSite.ed.edo02,ou=groups,dc=univ-paris1,dc=fr</cas:memberOf>
            <cas:memberOf>cn=applications.www.webmestre.miniSite.ufr.u04,ou=groups,dc=univ-paris1,dc=fr</cas:memberOf>
            <cas:memberOf>cn=applications.phraseanet.phototheque-dsiun,ou=groups,dc=univ-paris1,dc=fr</cas:memberOf>
            <cas:sn>Rigaux</cas:sn>
            </cas:attributes>
    </cas:authenticationSuccess>
</cas:serviceResponse>`

describe('getCasAuthSuccessValues', () => {
    it('should handle multi', () => {
        assert.deepStrictEqual(h.getCasAuthSuccessValues({ mono: {}, multi: { foo: 'foo' }}, `<cas:foo>Foo</cas:foo>`), {
            foo: ['Foo']
        })
    })

    it('overwrites mono', () => {
        assert.deepStrictEqual(h.getCasAuthSuccessValues({ mono: { foo: 'foo' }, multi: {}}, `<cas:foo>Foo1</cas:foo><cas:foo>Foo2</cas:foo>`), {
            foo: 'Foo2'
        })
    })

    it('should work for full serviceResponse', () => {
        assert.deepStrictEqual(h.getCasAuthSuccessValues(h.supann_to_oidc_attr, casAuthSuccessResponse), {
            subject: 'prigaux',
            email: 'Pascal.Rigaux@univ-paris1.fr',
            family_name: 'Rigaux',
            given_name: 'Pascal',
            preferred_username: 'Pascal Rigaux',
            eduperson_affiliation: [ 'member', 'employee', 'staff' ],
        })
    })

})
