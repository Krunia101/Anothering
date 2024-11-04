export interface ResponseSuccess2 {
    statuscode?: number;
    status: any;
    message: string;
    data?: any;
}

export interface ResponseUjian extends ResponseSuccess2 {
    pagination :{
        total: number;
        page: number;
        pagesize : number;
        totalpage: number;
    }
}