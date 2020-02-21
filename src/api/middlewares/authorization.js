class Authorization {

    static async authorize(req, res, next) {
        //some custom logic to authorise the ownership of the data. Might be used to validate that the provided path param ID corresponds to the caller
        next();
    }

}

module.exports = Authorization;