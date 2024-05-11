import Logger from './lib/Logger';
import { GameCenterSignatureValidator } from './lib/GameCenterSignatureValidator';

const logger = Logger.getInstance();

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {

        logger.setSilentMode(env.SILENCE_LOGGING.toLowerCase() === "true");

        const body = await request.json() as { timestamp: string | number; publicKeyUrl: string; signature: string; salt: string; playerId: string };
        body.timestamp = typeof body.timestamp === 'string' ? parseInt(body.timestamp, 10) : body.timestamp;
        if (env.BUNDLE_ID === "com.example.gamecenter") {
            logger.log("The `BUNDLE_ID` environment variable is set to the default value. Please set it either via the `wrangler.toml` file or the Cloudflare Workers Dashboard.");
            throw new Error("The `BUNDLE_ID` environment variable is set to the default value. Please set it either via the `wrangler.toml` file or the Cloudflare Workers Dashboard.");
        }

        const gameCenter = new GameCenterSignatureValidator(env.BUNDLE_ID);
        try {
            await gameCenter.authenticateGameCenterUser(
                body.publicKeyUrl,
                body.playerId,
                body.timestamp,
                body.salt,
                body.signature,
                env
            );
            return new Response(null, { status: 200 });
        } catch (error) {
            console.log("Error during authentication:", error);
            return new Response(null, { status: 400 });
        }
    },
};

