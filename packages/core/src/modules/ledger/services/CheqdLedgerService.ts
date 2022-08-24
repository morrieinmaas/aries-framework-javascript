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
import type Indy from 'indy-sdk'

import { AgentConfig } from '../../../agent/AgentConfig'
import { injectable } from '../../../plugins'
import { IndyWallet } from '../../../wallet/IndyWallet'
import { IndyIssuerService } from '../../indy/services/IndyIssuerService'

import { IndyPoolService } from './IndyPoolService'

@injectable()
export class CheqdLedgerSevice implements GenericIndyLedgerService {
  private wallet: IndyWallet
  private indy: typeof Indy
  private logger: Logger

  private indyIssuer: IndyIssuerService
  private indyPoolService: IndyPoolService

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

  // TODO-CHEQD: I don't think we would need to manually, if at all, deal with pools
  public connectToPools(): Promise<number[]> {
    throw new Error('Method not implemented.')
  }

  // TODO-CHEQD: implement
  public registerPublicDid(
    submitterDid: string,
    targetDid: string,
    verkey: string,
    alias: string,
    role?: Indy.NymRole
  ): Promise<string> {
    throw new Error('Method not implemented.')
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
