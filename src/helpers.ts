import express from 'express'
import { cas_server_base_url } from './config'

export interface Dictionary<T> { [key: string]: T; }

export interface to_oidc_attr { mono: Dictionary<string | ((value: string) => {attr: string, value: string}[])>, multi: Dictionary<string> }

// to remove with Express v5, see https://stackoverflow.com/a/38083802/3005203
export const handle_error = (callback: (req : express.Request, res: express.Response) => Promise<void>): express.RequestHandler => async (req, res) => {
    try {
        await callback(req, res)
    } catch (err) {
        console.error(err)
        const msg = `
        <div class="erreur">Erreur</div>
            ${err === 'LOGIN_REQUEST_EXPIRED' ? 
            `Il semble que vous soyez resté trop longtemps sur la page d'authentification.` : `Veuillez ré-essayer ultérieurement`}
        
            <button onclick="window.history.back()">Réessayer</button>
        </div>`
        res.send(msg)
    }
}

export const toArray = (s: string | string[]) => (
    typeof s === 'string' ? [s] : s
)

function decodeEntities(encodedString: string) {
    const translate_re = /&(apos|quot|amp|lt|gt);/g;
    const translate: Dictionary<string> = { apos: "'", quot: '"', amp : "&", lt  : "<", gt  : ">" };
    return encodedString
        .replace(translate_re, (_, entity) => (
            translate[entity]
        )).replace(/&#(\d+);/gi, (_, numStr) => (
            String.fromCharCode(parseInt(numStr, 10)) // needed for XML?
        ));
}

function getCasAuthSuccessValues(to_oidc_attr: to_oidc_attr, successXml: string) {
    let r: Dictionary<string|string[]> = {}
    for (const match of successXml.matchAll(/<cas:(\w+)>(.*?)<\/cas:\1>/g)) {
        const val = decodeEntities(match[2])
        const oidc_attr_mono = to_oidc_attr.mono[match[1]]
        if (oidc_attr_mono) {
            if (typeof oidc_attr_mono === 'function') {
                for (const { attr, value} of oidc_attr_mono(val)) {
                    r[attr] = value
                }
            } else {
                r[oidc_attr_mono] = val
            }
        } else {
            const oidc_attr_multi = to_oidc_attr.multi[match[1]]            
            if (oidc_attr_multi) {
                if (!r[oidc_attr_multi]) r[oidc_attr_multi] = []
                // @ts-expect-error
                r[oidc_attr_multi].push(val)
            }
        }
    }
    return r
}

export async function casv2_validate_ticket(to_oidc_attr: to_oidc_attr, ourUrl: string, ticket: string) {
    const params = { service: ourUrl, ticket }
    const url = cas_server_base_url + '/serviceValidate?' + new URLSearchParams(params).toString()
    const response = await fetch(url)
    if (response.ok) {
        const body = await response.text();
        if (body.match(/<cas:authenticationSuccess>/) && body.match(/<cas:user>(.*?)<\/cas:user>/)) {
            return getCasAuthSuccessValues(to_oidc_attr, body)
        }
        const err = body.match(/<cas:authenticationFailure code="(.*)">(.*?)</)
        if (err) throw { code: err[1], msg: err[2] }
    }
    throw { msg: "Problème technique, veuillez ré-essayer plus tard." }
}

export const export_for_tests = { getCasAuthSuccessValues }