import express from 'express'
import { cas_server_base_url, hydraAdmin, our_base_url, supann_to_oidc_attr, ticket_to_session_dir } from './config'
import { handle_error, casv2_validate_ticket } from './helpers'
import file_backed_dictionary from './file_backed_dictionary'

const router = express.Router()
const ticket_to_session = file_backed_dictionary(ticket_to_session_dir, {
    ttl_seconds: 7/*days*/ * 24*60*60,
    cleanup_frequency_seconds: 1/*hour*/ * 60*60,
})

router.post('/login', handle_error(async (req, res) => {
    const [,ticket] = req.body?.logoutRequest?.match(/<samlp:SessionIndex>([^<]*)</) ?? []
    if (ticket) {
        const session_id = await ticket_to_session.get_unset(ticket);
        if (session_id) {
            console.log(`revoking ${session_id}`)
            await hydraAdmin.revokeOAuth2LoginSessions({ sid: session_id })
        } else {
            console.warn("CAS backchannel logout request: Unknown ticket", ticket)
        }     
    } else {
        console.info("POST on /login should be a CAS backchannel request", req.body)
    }
    res.send('')
}))

router.get('/login', handle_error(async (req, res) => {
    const loginChallenge = String(req.query.login_challenge)
    if (!loginChallenge) throw new Error('Expected a login challenge')

    const { data: loginRequest } = await hydraAdmin.getOAuth2LoginRequest({ loginChallenge }) // needed?
    
    const ourUrl = our_base_url + '/login?login_challenge=' + encodeURIComponent(loginChallenge)
    if (!req.query.ticket) {
        res.redirect(cas_server_base_url + "/login?service=" + encodeURIComponent(ourUrl))
    } else {
        const ticket = String(req.query.ticket)
        const cas_response = await casv2_validate_ticket(supann_to_oidc_attr, ourUrl, ticket)

        if (!loginRequest.session_id) throw "internal error";

        // NB: not waiting for write to complete
        ticket_to_session.set(ticket, loginRequest.session_id)


        // tell hydra:
        const { data: acceptResp } = await hydraAdmin.acceptOAuth2LoginRequest({ loginChallenge, acceptOAuth2LoginRequest: { 
            // remember neccesary for revokeOAuth2LoginSessions by "sid" (cf HandleHeadlessLogout > GetRememberedLoginSession , https://github.com/ory/hydra/blob/master/consent/strategy_default.go#L1102 )
            remember: true,
            remember_for: 0, // pas d'expiration
            subject: String(cas_response.subject),
            context: cas_response,
        } })
        // redirect the user back to hydra
        res.redirect(String(acceptResp.redirect_to))
    }
}))

router.get('/consent', handle_error(async (req, res) => {
    const consentChallenge = String(req.query.consent_challenge)
    if (!consentChallenge) throw new Error('Expected a consent challenge')
    
    const { data: consentRequest } = await hydraAdmin.getOAuth2ConsentRequest({ consentChallenge })
    
    const { data: acceptResp } = await hydraAdmin.acceptOAuth2ConsentRequest({ consentChallenge, acceptOAuth2ConsentRequest: {
            // give what was requested and checked by hydra:
            grant_scope: consentRequest.requested_scope,
            grant_access_token_audience: consentRequest.requested_access_token_audience,

            session: {
              id_token: consentRequest.context,
            }
    } })
    // redirect the user back to hydra!
    res.redirect(String(acceptResp.redirect_to))
}))

router.get('/logout', handle_error(async (req, res) => {
    const logoutChallenge = String()
    if (!logoutChallenge) throw Error('Expected a logout challenge')
    await hydraAdmin.getOAuth2LogoutRequest({ logoutChallenge }) // needed?
    
    res.redirect(cas_server_base_url + '/logout')
}))

export default router
