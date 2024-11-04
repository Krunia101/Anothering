import { match } from 'assert';
import { ResponseSuccess2, ResponseUjian } from 'src/Interface';

class BaseResponse2 {
  _success(message: string, data: any): ResponseSuccess2 {
    return {
      status: 'Success',
      message: message,
      data: data || {},
    };
  }

  _pagination(
    message: string,
    data: any,
    total: number,
    page: number,
    pagesize: number,
  ): ResponseUjian {
    return {
      status: 'Success',
      message: message,
      pagination: {
        total: total,
        page: page,
        pagesize: pagesize,
        totalpage: Math.ceil(page / pagesize),
      },
    };
  }
}
export default BaseResponse2