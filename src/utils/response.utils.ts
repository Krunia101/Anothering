import { match } from 'assert';
import { ResponsePagination, ResponseSuccess } from 'src/Interpace';

class BaseResponse {
  _success(message: string, data?: any): ResponseSuccess {
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
  ): ResponsePagination {
    return {
      status: 'Success',
      message: message,
      data: data || {},
      pagination: {
        total: total,
        page: page,
        pagesize: pagesize,
        totalpage: Math.ceil(page / pagesize),
      },
    };
  }
}
export default BaseResponse