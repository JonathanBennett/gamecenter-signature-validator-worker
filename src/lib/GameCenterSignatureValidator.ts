import { Buffer } from 'node:buffer';
import { Certificate, CertificateChainValidationEngine } from 'pkijs';
import * as asn1js from 'asn1js';
import Logger from './Logger';



interface IGameCenterSignatureValidator {
	authenticateGameCenterUser(
		gcPublicKeyUrl: string,
		gcPlayerId: string,
		gcTimestamp: number,
		gcSalt: string,
		gcUnverifiedSignature: string,
		env: Env
	): Promise<boolean>;
}

class GameCenterSignatureValidator implements IGameCenterSignatureValidator {
	private bundleId!: string;

	private static readonly ONE_MINUTE_IN_MILLISECONDS = 60000;
	private static readonly DEFAULT_CACHE_SECONDS = 300;

	private static readonly logger = Logger.getInstance();

	constructor(bundleId: string) {
		if (!bundleId) throw new Error('Must supply bundle ID in environment variables');
		if (bundleId) this.bundleId = bundleId;
	}

	/**
	 * Authenticates a Game Center user by validating the signature using Apple's public key infrastructure.
	 * @param gcPublicKeyUrl The URL to the public key certificate.
	 * @param gcPlayerId The player's ID.
	 * @param gcTimestamp The timestamp of the request.
	 * @param gcSalt The salt used in the signature.
	 * @param gcUnverifiedSignature The base64 encoded signature to verify.
	 * @param env Environment variables containing URLs to root and intermediate CA certificates.
	 * @returns The player ID if authentication is successful.
	 * @throws Will throw an error if authentication fails.
	 */
	public async authenticateGameCenterUser(
		gcPublicKeyUrl: string,
		gcPlayerId: string,
		gcTimestamp: number,
		gcSalt: string,
		gcUnverifiedSignature: string,
		env: Env
	): Promise<boolean> {
		try {
			this.validateTimestamp(gcTimestamp);
			const publicKey = await this.fetchAndImportPublicKeys(gcPublicKeyUrl, env);
			const decodedSignature = Buffer.from(gcUnverifiedSignature, 'base64');
			const decodedSalt = Buffer.from(gcSalt, 'base64');
			const payload = this.buildPayload(gcPlayerId, gcTimestamp, decodedSalt);

			await this.verifySignature(publicKey, decodedSignature, payload);
			return true;
		} catch (error) {
			console.log('Error authenticating Game Center user:', error);
			throw new Error('Authentication failed due to an internal error.');
		}
	}

	/**
	 * Validates the timestamp to ensure it's within an acceptable range.
	 * @param gcTimestamp The timestamp of the Game Center authentication request.
	 * @throws Will throw an error if the timestamp is more than one minute old.
	 */
	private validateTimestamp(gcTimestamp: number): void {
		const currentTime = Date.now();
		if (currentTime - gcTimestamp > GameCenterSignatureValidator.ONE_MINUTE_IN_MILLISECONDS) {
			throw new Error('Timestamp is more than 1 minute old');
		}
	}

	/**
	 * Fetches and imports the public keys from specified URLs and validates the certificate chain.
	 * @param gcPublicKeyUrl The URL to the Game Center public key certificate.
	 * @param env Environment variables containing URLs to root and intermediate CA certificates.
	 * @returns A Promise resolving to the imported public key certificate.
	 * @throws Will throw an error if fetching, importing, or validating the public key fails.
	 */
	private async fetchAndImportPublicKeys(gcPublicKeyUrl: string, env: Env): Promise<Certificate> {
		try {
			const publicCA = await this.fetchPublicKeyCertificate(env.ROOT_CA_URL);
			const publicCACert = await this.importPublicKey(publicCA);
			const publicICA = await this.fetchPublicKeyCertificate(env.ICA_URL);
			const publicICACert = await this.importPublicKey(publicICA);

			const gcPKeyCertificate = await this.fetchPublicKeyCertificate(gcPublicKeyUrl);
			const publicKey = await this.importPublicKey(gcPKeyCertificate);

			const isAppleCertValid = await this.validateCertificateChain(publicKey, publicCACert, publicICACert);
			if (!isAppleCertValid) {
				throw new Error('Invalid Apple certificate chain.');
			}

			return publicKey;
		} catch (error) {
			console.error('Failed to fetch or import public key:', error);
			throw new Error('Failed to validate public key.');
		}
	}

	/**
	 * Verifies the digital signature using the provided public key and data.
	 * @param publicKey The public key certificate used for verification.
	 * @param signature The digital signature to verify.
	 * @param data The data that was signed.
	 * @throws Will throw an error if the signature verification fails.
	 */
	private async verifySignature(publicKey: Certificate, signature: Buffer, data: Uint8Array): Promise<void> {
		const cryptoKey = await publicKey.getPublicKey();
		const isValidSignature = await this.verifySignatureWithCrypto(cryptoKey, signature, data);
		if (!isValidSignature) {
			throw new Error('Invalid signature');
		}
	}

	/**
	 * Validates the certificate chain using the provided certificates.
	 * @param targetCert The target certificate to validate.
	 * @param caCert The root CA certificate.
	 * @param icaCert The intermediate CA certificate.
	 * @returns A Promise resolving to a boolean indicating if the validation was successful.
	 * @throws Will throw an error if the certificate chain validation fails.
	 */
	private async validateCertificateChain(targetCert: Certificate, caCert: Certificate, icaCert: Certificate): Promise<boolean> {
		const trustedCerts = [caCert];
		const certs = [caCert, icaCert, targetCert];

		const chainValidator = new CertificateChainValidationEngine({
			trustedCerts: trustedCerts,
			certs: certs,
		});

		const validationResult = await chainValidator.verify();
		if (!validationResult.result) {
			throw new Error('Certificate chain validation failed');
		}
		return validationResult.result;
	}

	/**
	 * Imports a public key from a PEM-formatted string.
	 * @param publicKey The PEM-formatted public key string.
	 * @returns A Promise resolving to the imported Certificate object.
	 * @throws Will throw an error if the public key cannot be parsed.
	 */
	private async importPublicKey(publicKey: string): Promise<Certificate> {
		const binaryDer = Buffer.from(publicKey, 'base64').buffer;
		const asn1 = asn1js.fromBER(binaryDer);
		if (asn1.offset === -1) {
			throw new Error('Cannot parse certificate ASN.1 data');
		}
		return new Certificate({ schema: asn1.result });
	}

	/**
	 * Fetches a public key certificate from a URL and caches it.
	 * @param url The URL from which to fetch the public key certificate.
	 * @returns A Promise resolving to the public key certificate as a string.
	 * @throws Will throw an error if the fetch operation fails.
	 */
	private async fetchPublicKeyCertificate(url: string): Promise<string> {
		try {
			const cacheUrl = new URL(url);
			const cache = caches.default;
			let response = await cache.match(cacheUrl);
			if (!response) {
				response = await fetch(url);
				if (!response.ok) {
					throw new Error(`Failed to fetch public key certificate ${url.split('/').pop()}: "${response.statusText}"`);
				}
				console.log(`Certificate downloaded for "${url.split('/').pop()}"`)
				await this.cacheResponse(response.clone(), url);
			} else {
				console.log(`Certificate returned from cache for "${url.split('/').pop()}"`);
			}
			return await this.extractCertificateFromResponse(response.clone());
		} catch (error) {
			console.error('Error fetching public key certificate:', error);
			throw new Error('Failed to fetch public key certificate due to network or server error.');
		}
	}

	/**
	 * Builds the payload used for signature verification.
	 * @param playerId The Game Center player ID.
	 * @param timestamp The timestamp of the request.
	 * @param salt The salt used in the signature.
	 * @returns A Uint8Array representing the concatenated payload.
	 */
	private buildPayload(playerId: string, timestamp: number, salt: Buffer): Uint8Array {
		const teamPlayerIDBytes = new TextEncoder().encode(playerId);
		const bundleIDBytes = new TextEncoder().encode(this.bundleId);

		// Convert timestamp to big-endian Uint8Array
		const timestampBytes = new Uint8Array(8);
		let bigEndianTimestamp = BigInt(timestamp);
		for (let i = 0; i < 8; i++) {
			timestampBytes[7 - i] = Number(bigEndianTimestamp & 0xffn);
			bigEndianTimestamp >>= 8n;
		}

		// Concatenate the data components
		return new Uint8Array([
			...teamPlayerIDBytes,
			...bundleIDBytes,
			...timestampBytes,
			...salt, //
		]);
	}

	private async verifySignatureWithCrypto(publicKey: CryptoKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
		try {
			const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
			const result = await crypto.subtle.verify(algorithm, publicKey, signature, data);
			if (!result) {
				throw new Error('Signature verification failed');
			}
			return result;
		} catch (error) {
			console.error('Error verifying signature with crypto:', error);
			throw new Error('Failed to verify signature due to cryptographic error.');
		}
	}

	// Helper method to cache responses
	private async cacheResponse(response: Response, url: string): Promise<void> {
		const maxAge = this.extractMaxAge(response);
		const headers = { 'cache-control': `public, max-age=${maxAge}` };
		const cache = caches.default;
		await cache.put(new URL(url), new Response(response.body, { ...response, headers }));
	}

	// Helper method to extract max-age from response headers
	private extractMaxAge(response: Response): number {
		const cacheControl = response.headers.get('cache-control');
		const match = cacheControl?.match(/max-age=(\d+)/);
		return match ? parseInt(match[1], 10) : GameCenterSignatureValidator.DEFAULT_CACHE_SECONDS;
	}

	// Helper method to extract certificate from response
	private async extractCertificateFromResponse(response: Response): Promise<string> {
		const buffer = await response.arrayBuffer();
		return btoa(String.fromCharCode(...new Uint8Array(buffer)));
	}
}

export { GameCenterSignatureValidator };
export type { IGameCenterSignatureValidator };
