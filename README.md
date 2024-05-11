# Gamecenter server-side player signature validation on Cloudflare Workers ☀️

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jonathanbennett/gamekit-signature-validation-worker)

## Overview

This project implements the server-side player signature validation for Game Center as a Cloudflare Workers, as described in the Apple documentation [^1]. It provides a secure and efficient way to authenticate Game Center users on your server-side applications at minimal cost and latency.

The project uses Cloudflare Workers [^2], a serverless platform that allows you to run custom code at the edge of the network, to validate the signature of Game Center users. This approach provides several benefits, including:

* Improved security: By validating the signature on the server-side, you can ensure that the user data is authentic and has not been tampered with.
* Better performance: Cloudflare Workers can handle the validation process at the edge of the network, reducing the latency and improving the overall user experience.
* Scalability: Cloudflare Workers can handle a large volume of requests without affecting the performance of your server-side application.

## Development

* Prerequesites: You need to have the cloudflare CLI installed to run any local development commands. Please install that first. [^4]

To set up this project for development, follow these steps:

1. Clone the repository and navigate to the project directory.
2. Install the dependencies by running `npm install` or `yarn install`.
3. Go into `wrangler.toml` and set the `[var]` called "BUNDLE_ID" to your bundle ID.
4. Run `yarn dev` to start the development server.
5. To deploy the worker to production, run `wrangler publish`.

## Environment Variables

The project uses the following environment variables:

* `BUNDLE_ID`: Your App Bundle ID.
* `ROOT_CA_URL`: The URL of the root CA certificate which signed Apple's Public Key (defaults to `https://knowledge.digicert.com/content/dam/kb/attachments/general/certificates/root/digicert-trusted-root-g4.cer`).
* `ICA_URL`: The URL of the intermediate CA certificate for the root CA (defaults to `https://knowledge.digicert.com/content/dam/kb/attachments/general/certificates/ica/digicert-trusted-g4-code-signing-rsa4096-sha384-2021-ca1.cer`).

Note: The `ROOT_CA_URL` and `ICA_URL` environment variables are provided in case the certificates change suddenly, and a redeploy will fix the issue with the correct URLs (as long as the newly issued certificates also generate the public key). The defaults were taken as per the notice available on Apple's last announcement about the certificate change[^3].

## Security Implementations

The project implements the following security measures:

1. Timestamp validation: The project checks if the timestamp is within 60 seconds of the current time to prevent replay attacks.
2. Certificate validation: The project validates the public key downloaded from the message against Apple's Root CA (Digicert) from their original sources and rejects any certificate that doesn't validate on the chain. For scalability, as per documentations, all certificates are cached for either their max-age header when retrieved, or 300 seconds if no max-header is present (as currently in the case of Digicert's cert).

## Usage

To use this project, you need to send the following parameters in the request:

* `timestamp`: The timestamp of the request.
* `publicKeyUrl`: The URL of the public key.
* `signature`: The base64-encoded signature.
* `salt`: The base64-encoded salt.
* `playerId`: The ID of the Game Center player.

```json
Content-type: application/json

{
  "timestamp": 1633036800,
  "publicKeyUrl": "https://example.com/publicKey.cer",
  "signature": "dGVzdFNpZ25hdHVyZQ==",
  "salt": "dGVzdFNhbHQ=",
  "playerId": "G123456789"
}
```

The project will validate the signature and return a `200 OK` response if the authentication is successful, or a `400 Bad Request` response if the authentication fails.

## Why is this needed?

This project implements the server-side player signature validation for Game Center as described in the Apple documentation. It uses Cloudflare Workers to validate the signature at the edge of the network, providing a secure and efficient way to authenticate Game Center users. When trying to find an implementation to reference to make sure it was correct, it was surprisingly hard to find a focussed project to a) learn from or b) deploy.

The project follows the guidelines outlined in the Apple documentation, including:

* Validating the timestamp to prevent replay attacks.
* Fetching and importing the public key from the provided URL.
* Decoding the base64-encoded signature and salt.
* Building the payload by concatenating the player ID, bundle ID, timestamp, and salt.
* Verifying the signature using the fetched public key.

The project also implements additional security measures, such as validating the certificate chain to ensure it's signed by Apple's recognized CA.

## Conclusion

This project provides a secure and efficient way to authenticate Game Center users on your server-side applications using Cloudflare Workers. It follows the guidelines outlined in the Apple documentation and implements additional security measures to ensure the integrity of the authentication process.

## References

[^1]: [GameKit LocalPlayer Fetch Items Documentation with Server Side Development Instructions](https://developer.apple.com/documentation/gamekit/gklocalplayer/3516283-fetchitems)
[^2]: [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
[^3]: [Apple Developer News Article - Get ready for a new Game Center authentication certificate - July 30, 2021](https://developer.apple.com/news/?id=stttq465)
[^4]: [Getting Started with Cloudflare Workers using Wrangler CLI](https://developers.cloudflare.com/workers/get-started/guide/#2-develop-with-wrangler-cli)

## Todo

[] Write tests
