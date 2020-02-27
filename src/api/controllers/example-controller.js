/**
 * Example controller that implements routes of the API.
 */
class ExampleController {

    static emptyRouter(req, res, next) {
        res.status(200).json({
            route: '/',
            status: 200
        });
    }

    static exampleRouter(req, res, next) {
        res.status(200).json({
            route: '/examples',
            status: 200
        });
    }

    /**
     * get information by specified param
     */
    static exampleRouterParam(req, res, next) {
        const id = req.params.id
        res.status(200).json({
            route: '/example/:id',
            id,
            status: 200
        });
    }
}

module.exports = ExampleController;