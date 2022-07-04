import { EventEmitter } from '../../../agent/EventEmitter'
import { InjectionSymbols } from '../../../constants'
import { injectable, inject } from '../../../plugins'
import { Repository } from '../../../storage/Repository'
import { StorageService } from '../../../storage/StorageService'

import { AnonCredsSchemaRecord } from './AnonCredsSchemaRecord'

@injectable()
export class AnonCredsSchemaRepository extends Repository<AnonCredsSchemaRecord> {
  public constructor(
    @inject(InjectionSymbols.StorageService) storageService: StorageService<AnonCredsSchemaRecord>,
    eventEmitter: EventEmitter
  ) {
    super(AnonCredsSchemaRecord, storageService, eventEmitter)
  }

  public async getBySchemaId(schemaId: string) {
    return this.getSingleByQuery({ schemaId: schemaId })
  }

  public async findBySchemaId(schemaId: string) {
    return await this.findSingleByQuery({ schemaId: schemaId })
  }
}
