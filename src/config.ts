import { OAuth2Api, Configuration } from '@ory/hydra-client'
import { to_oidc_attr } from './helpers'

const baseOptions: any = {}

if (process.env.MOCK_TLS_TERMINATION) {
  baseOptions.headers = { 'X-Forwarded-Proto': 'https' }
}

export const hydraAdmin = new OAuth2Api(
  new Configuration({
    basePath: 'http://127.0.0.1:4445',
    baseOptions
  })
)

export const our_base_url = 'https://oidc.univ.fr/hydra-cas-bridge'
export const cas_server_base_url = 'https://cas.univ.fr/cas'

export const ticket_to_session_dir = '/var/lib/hydra-cas-bridge--ticket-to-session';

// https://wiki.refeds.org/display/GROUPS/Mapping+SAML+attributes+to+OIDC+Claims
export const supann_to_oidc_attr: to_oidc_attr = {
    mono: {
        user: "subject",
        mail: "email",
        givenName: "given_name",
        sn: "family_name",
        displayName: "preferred_username",
    },
    multi: {
        eduPersonAffiliation: "eduperson_affiliation",
    },
}

