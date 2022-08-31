import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'

import { Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import { CredentialState, CredentialStateChangedEvent, Agent, CredentialEventTypes, LogLevel } from '../src'
import { sleep } from '../src/utils/sleep'

import { getBaseConfig, waitForCredentialRecord } from './helpers'
import { TestLogger } from './logger'

const logger = new TestLogger(LogLevel.debug)

const aliceConfig = getBaseConfig('cheqd alice', {
  logger,
  endpoints: ['rxjs:alice'],
})
const faberConfig = getBaseConfig('cheqd faber', {
  logger,
  endpoints: ['rxjs:faber'],
})

describe('Cheqd', () => {
  test('e2e flow', async () => {
    const faberMessages = new Subject<SubjectMessage>()
    const aliceMessages = new Subject<SubjectMessage>()
    const subjectMap = {
      'rxjs:faber': faberMessages,
      'rxjs:alice': aliceMessages,
    }

    const faberAgent = new Agent(faberConfig.config, faberConfig.agentDependencies)
    faberAgent.registerInboundTransport(new SubjectInboundTransport(faberMessages))
    faberAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await faberAgent.initialize()

    const aliceAgent = new Agent(aliceConfig.config, aliceConfig.agentDependencies)
    aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()

    const schema = await faberAgent.ledger.registerSchema({
      attributes: ['name', 'age'],
      name: 'test',
      version: '1.0',
    })

    expect(schema.id.includes('did:cheqd:testnet')).toBe(true)

    const retrievedSchema = await faberAgent.ledger.getSchema(schema.id)
    expect(retrievedSchema).toEqual(schema)

    console.log(retrievedSchema)

    const credentialDefinition = await faberAgent.ledger.registerCredentialDefinition({
      schema: retrievedSchema,
      supportRevocation: false,
      tag: 'hello',
    })

    expect(credentialDefinition.id.includes('did:cheqd:testnet')).toBe(true)
    const retrievedCredentialDefinition = await faberAgent.ledger.getCredentialDefinition(credentialDefinition.id)

    expect(retrievedCredentialDefinition).toEqual(credentialDefinition)

    console.log(retrievedCredentialDefinition)

    const faberOutOfBandRecord = await faberAgent.oob.createInvitation()

    const { connectionRecord: aliceConnectionRecord } = await aliceAgent.oob.receiveInvitation(
      faberOutOfBandRecord.outOfBandInvitation
    )

    if (!aliceConnectionRecord) throw new Error('No connection')

    await aliceAgent.connections.returnWhenIsConnected(aliceConnectionRecord.id)
    const [faberConnection] = await faberAgent.connections.findAllByOutOfBandId(faberOutOfBandRecord.id)

    let aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
      state: CredentialState.OfferReceived,
    })

    let faberCredentialRecord = await faberAgent.credentials.offerCredential({
      connectionId: faberConnection.id,
      protocolVersion: 'v2',
      credentialFormats: {
        indy: {
          attributes: [
            {
              name: 'name',
              value: 'Berend',
            },
            {
              name: 'age',
              value: '23',
            },
          ],
          credentialDefinitionId: credentialDefinition.id,
        },
      },
    })

    let aliceCredentialRecord = await aliceCredentialRecordPromise

    let faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
      state: CredentialState.RequestReceived,
      threadId: faberCredentialRecord.threadId,
    })
    await aliceAgent.credentials.acceptOffer({ credentialRecordId: aliceCredentialRecord.id })
    faberCredentialRecord = await faberCredentialRecordPromise

    aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
      state: CredentialState.CredentialReceived,
    })
    faberCredentialRecord = await faberAgent.credentials.acceptRequest({ credentialRecordId: faberCredentialRecord.id })
    aliceCredentialRecord = await aliceCredentialRecordPromise

    faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
      state: CredentialState.Done,
    })
    await aliceAgent.credentials.acceptCredential({ credentialRecordId: aliceCredentialRecord.id })

    faberCredentialRecord = await faberCredentialRecordPromise

    console.log(await aliceAgent.credentials.getFormatData(aliceCredentialRecord.id))

    await faberAgent.wallet.delete()
    await aliceAgent.wallet.delete()
    await faberAgent.shutdown()
    await aliceAgent.shutdown()
  })
})
