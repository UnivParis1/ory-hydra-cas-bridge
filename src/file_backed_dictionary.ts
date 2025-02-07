import { accessSync, constants } from "fs"
import { readdir, readFile, stat, unlink, writeFile } from "fs/promises"

export type options = {
    ttl_seconds: number
    cleanup_frequency_seconds: number
}

export default (dir: string, options: options) => {
    accessSync(dir, constants.W_OK);

    setInterval(async () => {
        const allowed_time = Date.now() - options.ttl_seconds * 1000
        for (const file_ of await readdir(dir)) {
            const file = `${dir}/${file_}`
            const { ctimeMs } = await stat(file)
            if (ctimeMs < allowed_time) {
                console.log("removing old session", file_)
                await unlink(file)
            }
        }
    }, options.cleanup_frequency_seconds * 1000)
    
    return {
        async get_unset(ticket: string) {
            const file = `${dir}/${ticket}`
            try {
                const session = await readFile(file, 'utf8');
                await unlink(file)
                return session
            } catch {
                return null
            }
        },
        async set(ticket: string, session: string) {
            await writeFile(`${dir}/${ticket}`, session);
        },
    }
}
