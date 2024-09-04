export type ClientPath = string | Iterable<number> | ArrayLike<number> | ArrayBuffer;
export type VaultPath = string | Iterable<number> | ArrayLike<number> | ArrayBuffer;
export type RecordPath = string | Iterable<number> | ArrayLike<number> | ArrayBuffer;
export type StoreKey = string | Iterable<number> | ArrayLike<number> | ArrayBuffer;
export interface ConnectionLimits {
    maxPendingIncoming?: number;
    maxPendingOutgoing?: number;
    maxEstablishedIncoming?: number;
    maxEstablishedOutgoing?: number;
    maxEstablishedPerPeer?: number;
    maxEstablishedTotal?: number;
}
export interface PeerAddress {
    known: string[];
    use_relay_fallback: boolean;
}
export interface AddressInfo {
    peers: Map<string, PeerAddress>;
    relays: string[];
}
export interface ClientAccess {
    useVaultDefault?: boolean;
    useVaultExceptions?: Map<VaultPath, boolean>;
    writeVaultDefault?: boolean;
    writeVaultExceptions?: Map<VaultPath, boolean>;
    cloneVaultDefault?: boolean;
    cloneVaultExceptions?: Map<VaultPath, boolean>;
    readStore?: boolean;
    writeStore?: boolean;
}
export interface Permissions {
    default?: ClientAccess;
    exceptions?: Map<VaultPath, ClientAccess>;
}
export interface NetworkConfig {
    requestTimeout?: Duration;
    connectionTimeout?: Duration;
    connectionsLimit?: ConnectionLimits;
    enableMdns?: boolean;
    enableRelay?: boolean;
    addresses?: AddressInfo;
    peerPermissions?: Map<string, Permissions>;
    permissionsDefault?: Permissions;
}
/** A duration definition. */
export interface Duration {
    /** The number of whole seconds contained by this Duration. */
    secs: number;
    /** The fractional part of this Duration, in nanoseconds. Must be greater or equal to 0 and smaller than 1e+9 (the max number of nanoseoncds in a second) */
    nanos: number;
}
export declare class Location {
    type: string;
    payload: Record<string, unknown>;
    constructor(type: string, payload: Record<string, unknown>);
    static generic(vault: VaultPath, record: RecordPath): Location;
    static counter(vault: VaultPath, counter: number): Location;
}
declare class ProcedureExecutor {
    procedureArgs: Record<string, unknown>;
    constructor(procedureArgs: Record<string, unknown>);
    /**
     * Generate a SLIP10 seed for the given location.
     * @param outputLocation Location of the record where the seed will be stored.
     * @param sizeBytes The size in bytes of the SLIP10 seed.
     * @param hint The record hint.
     * @returns
     */
    generateSLIP10Seed(outputLocation: Location, sizeBytes?: number): Promise<Uint8Array>;
    /**
     * Derive a SLIP10 private key using a seed or key.
     * @param chain The chain path.
     * @param source The source type, either 'Seed' or 'Key'.
     * @param sourceLocation The source location, must be the `outputLocation` of a previous call to `generateSLIP10Seed` or `deriveSLIP10`.
     * @param outputLocation Location of the record where the private key will be stored.
     * @param hint The record hint.
     * @returns
     */
    deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location): Promise<Uint8Array>;
    /**
     * Store a BIP39 mnemonic.
     * @param mnemonic The mnemonic string.
     * @param outputLocation The location of the record where the BIP39 mnemonic will be stored.
     * @param passphrase The optional mnemonic passphrase.
     * @param hint The record hint.
     * @returns
     */
    recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string): Promise<Uint8Array>;
    /**
     * Generate a BIP39 seed.
     * @param outputLocation The location of the record where the BIP39 seed will be stored.
     * @param passphrase The optional mnemonic passphrase.
     * @param hint The record hint.
     * @returns
     */
    generateBIP39(outputLocation: Location, passphrase?: string): Promise<Uint8Array>;
    /**
     * Gets the Ed25519 public key of a SLIP10 private key.
     * @param privateKeyLocation The location of the private key. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
     * @returns A promise resolving to the public key hex string.
     *
     * @since 2.0.0
     */
    getEd25519PublicKey(privateKeyLocation: Location): Promise<Uint8Array>;
    /**
     * Creates a Ed25519 signature from a private key.
     * @param privateKeyLocation The location of the record where the private key is stored. Must be the `outputLocation` of a previous call to `deriveSLIP10`.
     * @param msg The message to sign.
     * @returns A promise resolving to the signature hex string.
     *
     * @since 2.0.0
     */
    signEd25519(privateKeyLocation: Location, msg: string): Promise<Uint8Array>;
}
export declare class Client {
    path: string;
    name: ClientPath;
    constructor(path: string, name: ClientPath);
    /**
     * Get a vault by name.
     * @param name
     * @param flags
     * @returns
     */
    getVault(name: VaultPath): Vault;
    getStore(): Store;
}
export declare class Store {
    path: string;
    client: ClientPath;
    constructor(path: string, client: ClientPath);
    get(key: StoreKey): Promise<Uint8Array | null>;
    insert(key: StoreKey, value: number[], lifetime?: Duration): Promise<void>;
    remove(key: StoreKey): Promise<Uint8Array | null>;
}
/**
 * A key-value storage that allows create, update and delete operations.
 * It does not allow reading the data, so one of the procedures must be used to manipulate
 * the stored data, allowing secure storage of secrets.
 */
export declare class Vault extends ProcedureExecutor {
    /** The vault path. */
    path: string;
    client: ClientPath;
    /** The vault name. */
    name: VaultPath;
    constructor(path: string, client: ClientPath, name: VaultPath);
    /**
     * Insert a record to this vault.
     * @param location The record location.
     * @param record  The record data.
     * @param recordHint The record hint.
     * @returns
     */
    insert(recordPath: RecordPath, secret: number[]): Promise<void>;
    /**
     * Remove a record from the vault.
     * @param location The record location.
     * @param gc Whether to additionally perform the gargage collection or not.
     * @returns
     */
    remove(location: Location): Promise<void>;
}
/**
 * A representation of an access to a stronghold.
 */
export declare class Stronghold {
    path: string;
    /**
     * Initializes a stronghold.
     * If the snapshot path located at `path` exists, the password must match.
     * @param path
     * @param password
     */
    private constructor();
    /**
     * Load the snapshot if it exists (password must match), or start a fresh stronghold instance otherwise.
     * @param password
     * @returns
     */
    static load(path: string, password: string): Promise<Stronghold>;
    /**
     * Remove this instance from the cache.
     */
    unload(): Promise<void>;
    loadClient(client: ClientPath): Promise<Client>;
    createClient(client: ClientPath): Promise<Client>;
    /**
     * Persists the stronghold state to the snapshot.
     * @returns
     */
    save(): Promise<void>;
}
export {};
