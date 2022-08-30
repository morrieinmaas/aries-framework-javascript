import type { IndyEndpointAttrib } from '../services'
import type {
  CredentialDefinitionTemplate,
  ParseRevocationRegistryDefinitionTemplate,
  ParseRevocationRegistryDeltaTemplate,
  ParseRevocationRegistryTemplate,
  SchemaTemplate,
} from '@aries-framework/core'
import type { CredDef, GetNymResponse, NymRole, Schema } from 'indy-sdk'

export const GenericIndyLedgerService = Symbol('GenericIndyLedgerService')

export interface GenericIndyLedgerService {
  connectToPools(): Promise<Array<number>>

  registerPublicDid(
    submitterDid: string,
    targetDid: string,
    verkey: string,
    alias: string,
    role?: NymRole
  ): Promise<string>

  getPublicDid(did: string): Promise<GetNymResponse>

  getEndpointsForDid(did: string): Promise<IndyEndpointAttrib>

  registerSchema(did: string, schemaTemplate: SchemaTemplate): Promise<Schema>

  getSchema(schemaId: string): Promise<Schema>

  registerCredentialDefinition(
    did: string,
    credentialDefinitionTemplate: CredentialDefinitionTemplate
  ): Promise<CredDef>

  getCredentialDefinition(credentialDefinitionId: string): Promise<CredDef>

  getRevocationRegistryDefinition(
    revocationRegistryDefinitionId: string
  ): Promise<ParseRevocationRegistryDefinitionTemplate>

  getRevocationRegistryDelta(
    revocationRegistryDefinitionId: string,
    to: number,
    from: number
  ): Promise<ParseRevocationRegistryDeltaTemplate>

  getRevocationRegistry(
    revocationRegistryDefinitionId: string,
    timestamp: number
  ): Promise<ParseRevocationRegistryTemplate>
}
