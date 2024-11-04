import { Injectable } from '@nestjs/common';

@Injectable()
export class LatihanService {
    findAll(query: any) {
        return {
            msg: 'Ready for service ',
        };
    }
    findDetail(id: string, name: string) {
        return {
            method: 'GET',
            id: `Id player adalah ${id}`,
            name: `Nama player adalah ${name}`,
            }
        }
    register(payload:any) {
        return {
            method : 'GET',
            payload : payload
          }
    }
    updater(id: string,payload:any) {
        return {
            method : 'GET',
            payload : payload
          }
    }
}