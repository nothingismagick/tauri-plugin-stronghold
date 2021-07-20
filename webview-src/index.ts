import { invoke } from '@tauri-apps/api/tauri'
import { listen } from '@tauri-apps/api/event'

export interface Duration {
  millis: number
  nanos: number
}

export interface Status {
  snapshot: {
    status: string
    data?: Duration
  }
}

export interface SwarmInfo {
  peerId: string
  listeningAddresses: string[]
}

export enum RelayDirection {
  Dialing,
  Listening,
  Both
}

export enum RequestPermission {
  CheckVault,
  CheckRecord,
  WriteToStore,
  ReadFromStore,
  DeleteFromStore,
  CreateNewVault,
  WriteToVault,
  RevokeData,
  GarbageCollect,
  ListIds,
  ReadSnapshot,
  WriteSnapshot,
  FillSnapshot,
  ClearCache,
  ControlRequest,
}

interface StatusListener {
  id: string
  cb: (status: Status) => void
}

type Unregister = () => void

const statusChangeListeners: { [snapshotPath: string]: StatusListener[] } = {}

listen('stronghold://status-change', event => {
  const { snapshotPath, status } = event.payload as any
  for (const listener of (statusChangeListeners[snapshotPath] || [])) {
    listener.cb(status)
  }
})

function s4() {
  return Math.floor((1 + Math.random()) * 0x10000)
    .toString(16)
    .substring(1)
}
function uid() {
  return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
    s4() + '-' + s4() + s4() + s4()
}

export enum StrongholdFlag { }

export class Location {
  type: string
  payload: { [key: string]: any }

  constructor(type: string, payload: { [key: string]: any }) {
    this.type = type
    this.payload = payload
  }

  static generic(vaultName: string, recordName: string) {
    return new Location('Generic', {
      vault: vaultName,
      record: recordName
    })
  }

  static counter(vaultName: string, counter: number) {
    return new Location('Counter', {
      vault: vaultName,
      counter
    })
  }
}

// array with length 24
export type RecordHint = [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number]

export function setPasswordClearInterval(interval: Duration) {
  return invoke('plugin:stronghold|set_password_clear_interval', {
    interval
  })
}

class ProcedureExecutor {
  procedureArgs: { [k: string]: any }
  command: string

  constructor(isRemote: boolean, procedureArgs: { [k: string]: any }) {
    this.procedureArgs = procedureArgs
    this.command = isRemote ? 'execute_remote_procedure' : 'execute_procedure'
  }

  generateSLIP10Seed(outputLocation: Location, sizeBytes?: number, hint?: RecordHint): Promise<void> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'SLIP10Generate',
        payload: {
          output: outputLocation,
          sizeBytes,
          hint
        }
      }
    })
  }

  deriveSLIP10(chain: number[], source: 'Seed' | 'Key', sourceLocation: Location, outputLocation: Location, hint?: RecordHint): Promise<string> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'SLIP10Derive',
        payload: {
          chain,
          input: {
            type: source,
            payload: sourceLocation
          },
          output: outputLocation,
          hint
        }
      }
    })
  }

  recoverBIP39(mnemonic: string, outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'BIP39Recover',
        payload: {
          mnemonic,
          passphrase,
          output: outputLocation,
          hint
        }
      }
    })
  }

  generateBIP39(outputLocation: Location, passphrase?: string, hint?: RecordHint): Promise<void> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'BIP39Generate',
        payload: {
          output: outputLocation,
          passphrase,
          hint
        }
      }
    })
  }

  getPublicKey(privateKeyLocation: Location): Promise<string> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'Ed25519PublicKey',
        payload: {
          privateKey: privateKeyLocation
        }
      }
    })
  }

  sign(privateKeyLocation: Location, msg: string): Promise<string> {
    return invoke(`plugin:stronghold|${this.command}`, {
      ...this.procedureArgs,
      procedure: {
        type: 'Ed25519Sign',
        payload: {
          privateKey: privateKeyLocation,
          msg
        }
      }
    })
  }
}

export class RemoteStore {
  path: string
  peerId: string

  constructor(path: string, peerId: string) {
    this.path = path
    this.peerId = peerId
  }

  get(location: Location): Promise<string> {
    return invoke('plugin:stronghold|get_remote_store_record', {
      snapshotPath: this.path,
      peerId: this.peerId,
      location
    })
  }

  insert(location: Location, record: string, lifetime?: Duration): Promise<void> {
    return invoke('plugin:stronghold|save_remote_store_record', {
      snapshotPath: this.path,
      peerId: this.peerId,
      location,
      record,
      lifetime
    })
  }
}

export class RemoteVault extends ProcedureExecutor {
  path: string
  peerId: string

  constructor(path: string, peerId: string) {
    super(true, {
      peerId
    })
    this.path = path
    this.peerId = peerId
  }
}

export class Store {
  path: string
  name: string
  flags: StrongholdFlag[]

  constructor(path: string, name: string, flags: StrongholdFlag[]) {
    this.path = path
    this.name = name
    this.flags = flags
  }

  private get vault() {
    return {
      name: this.name,
      flags: this.flags
    }
  }

  get(location: Location): Promise<string> {
    return invoke('plugin:stronghold|get_store_record', {
      snapshotPath: this.path,
      vault: this.vault,
      location
    })
  }

  insert(location: Location, record: string, lifetime?: Duration): Promise<void> {
    return invoke('plugin:stronghold|save_store_record', {
      snapshotPath: this.path,
      vault: this.vault,
      location,
      record,
      lifetime
    })
  }

  remove(location: Location): Promise<void> {
    return invoke('plugin:stronghold|remove_store_record', {
      snapshotPath: this.path,
      vault: this.vault,
      location
    })
  }
}

export class Vault extends ProcedureExecutor {
  path: string
  name: string
  flags: StrongholdFlag[]

  constructor(path: string, name: string, flags: StrongholdFlag[]) {
    super(false, {
      snapshotPath: path,
      vault: {
        name,
        flags
      }
    })
    this.path = path
    this.name = name
    this.flags = flags
  }

  private get vault() {
    return {
      name: this.name,
      flags: this.flags
    }
  }

  insert(location: Location, record: string, recordHint?: RecordHint): Promise<void> {
    return invoke('plugin:stronghold|save_record', {
      snapshotPath: this.path,
      vault: this.vault,
      location,
      record,
      recordHint,
      flags: []
    })
  }

  remove(location: Location, gc = true): Promise<void> {
    return invoke('plugin:stronghold|remove_record', {
      snapshotPath: this.path,
      vault: this.vault,
      location,
      gc
    })
  }
}

export class Communication {
  path: string

  constructor(path: string) {
    this.path = path
  }

  stop(): Promise<void> {
    return invoke('plugin:stronghold|stop_communication', {
      snapshotPath: this.path
    })
  }

  startListening(addr?: string): Promise<string> {
    return invoke('plugin:stronghold|start_listening', {
      snapshotPath: this.path,
      addr
    })
  }

  getSwarmInfo(): Promise<SwarmInfo> {
    return invoke('plugin:stronghold|get_swarm_info', { snapshotPath: this.path })
  }

  addPeer(peerId: string, addr?: string, relayDirection?: RelayDirection): Promise<string> {
    return invoke('plugin:stronghold|add_peer', {
      snapshotPath: this.path,
      peerId,
      addr,
      relayDirection: relayDirection ? { type: RelayDirection[relayDirection] } : null
    })
  }

  changeRelayDirection(peerId: string, relayDirection: RelayDirection): Promise<string> {
    return invoke('plugin:stronghold|change_relay_direction', {
      snapshotPath: this.path,
      peerId,
      relayDirection: { type: RelayDirection[relayDirection] }
    })
  }

  removeRelay(peerId: string): Promise<void> {
    return invoke('plugin:stronghold|remove_relay', {
      snapshotPath: this.path,
      peerId
    })
  }

  allowAllRequests(peers: string[], setDefault = false): Promise<void> {
    return invoke('plugin:stronghold|allow_all_requests', {
      snapshotPath: this.path,
      peers,
      setDefault
    })
  }

  rejectAllRequests(peers: string[], setDefault = false): Promise<void> {
    return invoke('plugin:stronghold|reject_all_requests', {
      snapshotPath: this.path,
      peers,
      setDefault
    })
  }

  allowRequests(peers: string[], permissions: RequestPermission[], changeDefault = false): Promise<void> {
    return invoke('plugin:stronghold|allow_requests', {
      snapshotPath: this.path,
      peers,
      requests: permissions.map(p => ({ type: RequestPermission[p] })),
      changeDefault
    })
  }

  rejectRequests(peers: string[], permissions: RequestPermission[], changeDefault = false): Promise<void> {
    return invoke('plugin:stronghold|reject_requests', {
      snapshotPath: this.path,
      peers,
      requests: permissions.map(p => ({ type: RequestPermission[p] })),
      changeDefault
    })
  }

  removeFirewallRules(peers: string[]): Promise<void> {
    return invoke('plugin:stronghold|remove_firewall_rules', {
      snapshotPath: this.path,
      peers
    })
  }

  getRemoteVault(peerId: string): RemoteVault {
    return new RemoteVault(this.path, peerId)
  }

  getRemoteStore(peerId: string): RemoteStore {
    return new RemoteStore(this.path, peerId)
  }
}

export class Stronghold {
  path: string

  constructor(path: string, password: string) {
    this.path = path
    this.reload(password)
  }

  reload(password: string): Promise<void> {
    return invoke('plugin:stronghold|init', {
      snapshotPath: this.path,
      password
    })
  }

  unload(): Promise<void> {
    return invoke('plugin:stronghold|destroy', {
      snapshotPath: this.path
    })
  }

  getVault(name: string, flags: StrongholdFlag[]): Vault {
    return new Vault(this.path, name, flags)
  }

  getStore(name: string, flags: StrongholdFlag[]): Store {
    return new Store(this.path, name, flags)
  }

  save(): Promise<void> {
    return invoke('plugin:stronghold|save_snapshot', {
      snapshotPath: this.path
    })
  }

  getStatus(): Promise<Status> {
    return invoke('plugin:stronghold|get_status', {
      snapshotPath: this.path
    })
  }

  onStatusChange(cb: (status: Status) => void): Unregister {
    if (statusChangeListeners[this.path] === void 0) {
      statusChangeListeners[this.path] = []
    }
    const id = uid()
    statusChangeListeners[this.path].push({
      id,
      cb
    })
    return () => {
      statusChangeListeners[this.path] = statusChangeListeners[this.path].filter(listener => listener.id !== id)
    }
  }

  spawnCommunication(): Promise<Communication> {
    return invoke('plugin:stronghold|spawn_communication', {
      snapshotPath: this.path
    }).then(() => new Communication(this.path))
  }
}
