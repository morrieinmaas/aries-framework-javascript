import type { Logger } from '../../../logger'
import type { GenericIndyLedgerService } from '../models/IndyLedgerService'
import type {
  IndyEndpointAttrib,
  SchemaTemplate,
  CredentialDefinitionTemplate,
  ParseRevocationRegistryDefinitionTemplate,
  ParseRevocationRegistryDeltaTemplate,
  ParseRevocationRegistryTemplate,
} from './IndyLedgerService'
import type { CheqdSDK, ICheqdSDKOptions } from '@cheqd/sdk'
import type { AbstractCheqdSDKModule } from '@cheqd/sdk/build/modules/_'
import type { DidStdFee, IContext } from '@cheqd/sdk/build/types'
import type { TImportableEd25519Key } from '@cheqd/sdk/build/utils'
import type { MsgCreateDidPayload, MsgUpdateDidPayload } from '@cheqd/ts-proto/cheqd/v1/tx'
import type Indy from 'indy-sdk'

import { DIDModule, createCheqdSDK } from '@cheqd/sdk'
import { createSignInputsFromImportableEd25519Key } from '@cheqd/sdk/build/utils'
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing'
import { subscribeOn } from 'rxjs'

import { AgentConfig } from '../../../agent/AgentConfig'
import { AriesFrameworkError } from '../../../error'
import { injectable } from '../../../plugins'
import { IndyWallet } from '../../../wallet/IndyWallet'
import { Key } from '../../dids'
import { IndyIssuerService } from '../../indy/services/IndyIssuerService'

import { IndyPoolService } from './IndyPoolService'

// --------------

const assert = (b: boolean, msg: string) => {
  if (b) return

  throw new AriesFrameworkError(msg)
}

export type IdentifierPayload = Partial<MsgCreateDidPayload> | Partial<MsgUpdateDidPayload>

// --------------

@injectable()
export class CheqdLedgerSevice implements GenericIndyLedgerService {
  private wallet: IndyWallet
  private indy: typeof Indy
  private logger: Logger

  private indyIssuer: IndyIssuerService
  private indyPoolService: IndyPoolService

  private sdk?: CheqdSDK
  private fee?: DidStdFee

  public constructor(
    wallet: IndyWallet,
    agentConfig: AgentConfig,
    indyIssuer: IndyIssuerService,
    indyPoolService: IndyPoolService
  ) {
    this.wallet = wallet
    this.indy = agentConfig.agentDependencies.indy
    this.logger = agentConfig.logger
    this.indyIssuer = indyIssuer
    this.indyPoolService = indyPoolService
  }

  private async getCheqdSDK(fee?: DidStdFee): Promise<CheqdSDK> {
    const COSMOS_PAYER_MNEMONIC = 'TODO-CHEQD'
    const RPC_URL = 'https://rpc.cheqd.network'
    const COSMOS_PAYER_WALLET = await DirectSecp256k1HdWallet.fromMnemonic(COSMOS_PAYER_MNEMONIC, { prefix: 'cheqd' })

    if (this.sdk) return this.sdk

    const sdkOptions: ICheqdSDKOptions = {
      modules: [DIDModule as unknown as AbstractCheqdSDKModule],
      rpcUrl: RPC_URL,
      wallet: COSMOS_PAYER_WALLET,
    }

    this.sdk = await createCheqdSDK(sdkOptions)
    this.fee = fee || {
      amount: [
        {
          denom: 'ncheq',
          amount: '5000000',
        },
      ],
      gas: '200000',
      payer: (await sdkOptions.wallet.getAccounts())[0].address,
    }
    return this.sdk
  }

  /**
   * https://github.com/cheqd/did-provider-cheqd/blob/7698f320ead5d9b4e278ac13cd9319dd5115cb83/src/did-manager/cheqd-did-provider.ts#L95
   */
  private async createIdentifier({
    options,
  }: {
    alias?: string
    options: { document: IdentifierPayload; keys: TImportableEd25519Key[] }
  }): Promise<string> {
    const sdk = await this.getCheqdSDK()

    const signInputs = options.keys.map((key) =>
      createSignInputsFromImportableEd25519Key(key, options.document.verificationMethod ?? [])
    )

    const tx = await sdk.createDidTx(signInputs, options.document, '', this.fee || 'auto', undefined, { sdk })

    assert(tx.code === 0, `cosmos_transaction: Failed to create DID. Reason: ${tx.rawLog}`)

    // TODO-CHEQD: this will just use the `targetDid` as supplied in the registerPublicDid function
    // Is this correct?
    const did = options.document.id

    return did as string
  }

  // TODO-CHEQD: I don't think we would need to manually, if at all, deal with pools
  public connectToPools(): Promise<number[]> {
    throw new Error('Method not implemented.')
  }

  // TODO-CHEQD: implement
  public async registerPublicDid(
    submitterDid: string,
    targetDid: string,
    verkey: string,
    alias: string,
    role?: Indy.NymRole
  ): Promise<string> {
    // TODO-CHEQD: create/get a keypair from wallet
    const key: TImportableEd25519Key = { type: 'Ed25519', privateKeyHex: '0xa', kid: 'kid', publicKeyHex: '0xa' }
    const sdk = await this.getCheqdSDK()
    const identifier = await this.createIdentifier(
      { options: { document: { id: targetDid, alsoKnownAs: [alias] }, keys: [key] } },
      { sdk }
    )

    return identifier
  }

  // TODO-CHEQD: implement
  public getPublicDid(did: string): Promise<Indy.GetNymResponse> {
    throw new Error('Method not implemented.')
  }

  // TODO-CHEQD: implement
  public registerSchema(did: string, schemaTemplate: SchemaTemplate): Promise<Indy.Schema> {
    throw new Error('Method not implemented.')
  }

  // TODO-CHEQD: implement
  public getSchema(schemaId: string): Promise<Indy.Schema> {
    throw new Error('Method not implemented.')
  }

  // TODO-CHEQD: implement
  public registerCredentialDefinition(
    did: string,
    credentialDefinitionTemplate: CredentialDefinitionTemplate
  ): Promise<Indy.CredDef> {
    throw new Error('Method not implemented.')
  }

  // TODO-CHEQD: implement
  public getCredentialDefinition(credentialDefinitionId: string): Promise<Indy.CredDef> {
    throw new Error('Method not implemented.')
  }

  public getRevocationRegistryDefinition(
    revocationRegistryDefinitionId: string
  ): Promise<ParseRevocationRegistryDefinitionTemplate> {
    throw new Error('Method not implemented.')
  }

  public getEndpointsForDid(did: string): Promise<IndyEndpointAttrib> {
    throw new Error('Method not implemented.')
  }

  public getRevocationRegistryDelta(
    revocationRegistryDefinitionId: string,
    to: number,
    from: number
  ): Promise<ParseRevocationRegistryDeltaTemplate> {
    throw new Error('Method not implemented.')
  }

  public getRevocationRegistry(
    revocationRegistryDefinitionId: string,
    timestamp: number
  ): Promise<ParseRevocationRegistryTemplate> {
    throw new Error('Method not implemented.')
  }
}
