import { JsonTransformer } from '../../../../../utils'
import { OutOfBandDidCommService } from '../../../../oob/domain/OutOfBandDidCommService'
import { DidDocument } from '../../../domain'
import { didToNumAlgo2DidDocument, didDocumentToNumAlgo2Did, outOfBandServiceToNumAlgo2Did } from '../peerDidNumAlgo2'

import didPeer2Ez6L from './__fixtures__/didPeer2Ez6L.json'
import didPeer2Ez6LMoreServices from './__fixtures__/didPeer2Ez6LMoreServices.json'

describe('peerDidNumAlgo2', () => {
  describe('didDocumentToNumAlgo2Did', () => {
    test('transforms method 2 peer did to a did document', async () => {
      await expect(async () => (await didToNumAlgo2DidDocument(didPeer2Ez6L.id)).toJSON()).resolves.toEqual(
        didPeer2Ez6L
      )

      await expect(async () => (await didToNumAlgo2DidDocument(didPeer2Ez6LMoreServices.id)).toJSON()).resolves.toEqual(
        didPeer2Ez6LMoreServices
      )
    })
  })

  describe('didDocumentToNumAlgo2Did', () => {
    test('transforms method 2 peer did document to a did', () => {
      const expectedDid = didPeer2Ez6L.id

      const didDocument = JsonTransformer.fromJSON(didPeer2Ez6L, DidDocument, { validate: false })

      expect(didDocumentToNumAlgo2Did(didDocument)).toBe(expectedDid)
    })
  })

  describe('outOfBandServiceToNumAlgo2Did', () => {
    test('transforms a did comm service into a valid method 2 did', async () => {
      const service = new OutOfBandDidCommService({
        id: '#service-0',
        serviceEndpoint: 'https://example.com/endpoint',
        recipientKeys: ['did:key:z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'],
        routingKeys: ['did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'],
        accept: ['didcomm/v2', 'didcomm/aip2;env=rfc587'],
      })
      const peerDid = outOfBandServiceToNumAlgo2Did(service)
      const peerDidDocument = await didToNumAlgo2DidDocument(peerDid)

      expect(peerDid).toBe(
        'did:peer:2.SeyJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInQiOiJkaWQtY29tbXVuaWNhdGlvbiIsInByaW9yaXR5IjowLCJyZWNpcGllbnRLZXlzIjpbImRpZDprZXk6ejZNa3FSWXFRaVNndlpRZG5CeXR3ODZRYnMyWldVa0d2MjJvZDkzNVlGNHM4TTdWI3o2TWtxUllxUWlTZ3ZaUWRuQnl0dzg2UWJzMlpXVWtHdjIyb2Q5MzVZRjRzOE03ViJdLCJyIjpbImRpZDprZXk6ejZNa3BUSFI4Vk5zQnhZQUFXSHV0MkdlYWRkOWpTd3VCVjh4Um9BbndXc2R2a3RII3o2TWtwVEhSOFZOc0J4WUFBV0h1dDJHZWFkZDlqU3d1QlY4eFJvQW53V3Nkdmt0SCJdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdfQ'
      )
      expect(peerDid).toBe(peerDidDocument.id)
    })
  })
})
